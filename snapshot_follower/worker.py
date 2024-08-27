import contextlib
import hashlib
import json
import re
import shutil
import threading
import uuid
import zipfile
from pathlib import Path
from typing import Optional, Type, TypeVar, Any

import requests
from mcdreforged.api.all import PluginServerInterface

from snapshot_follower.config import Config

_T = TypeVar('_T')


def _ensure_type(obj: Any, typ: Type[_T]) -> _T:
	if not isinstance(obj, typ):
		raise TypeError(f'Bad type for object {obj!r}, expected {typ}, found {type(obj)}')
	return obj


class _StopException(Exception):
	pass


class SnapshotFollowerWorker:
	def __init__(self, server: PluginServerInterface, config: Config):
		self.server = server
		self.logger = server.logger
		self.config = config
		self.__thread: Optional[threading.Thread] = None
		self.__stop_event = threading.Event()
		self.__prev_snapshot: Optional[str] = None

	def start(self):
		if self.__thread is not None:
			raise RuntimeError('double start')
		self.__thread = threading.Thread(target=self.__thread_loop, name='SFWorker@' + uuid.uuid4().hex[:4], daemon=True)
		self.__thread.start()

	def stop(self):
		self.__stop_event.set()
		self.__thread.join(timeout=60)
		if self.__thread.is_alive():
			self.logger.warning('worker thread is still alive, exit anyway')

	def __check_for_stop(self):
		if self.__stop_event.is_set():
			raise _StopException()

	@classmethod
	def __get_version_from_server_jar(cls, jar_path: Path) -> str:
		with zipfile.ZipFile(jar_path, 'r') as zipf:
			with zipf.open('version.json', 'r') as f:
				version_info = json.load(f)
		return _ensure_type(version_info['id'], str)

	@classmethod
	def __calc_file_sha1(cls, path: Path) -> str:
		hasher = hashlib.sha1()
		with open(path, 'rb') as f:
			while chunk := f.read(16384):
				hasher.update(chunk)
		return hasher.hexdigest()

	def __read_server_jar_version(self):
		jar_path = Path(self.config.server_jar_path)
		try:
			server_jar_version = self.__get_version_from_server_jar(jar_path)
		except Exception:
			self.logger.exception(f'Get version from server jar {str(jar_path)!r} failed, assuming it\'s the latest snapshot')
		else:
			self.logger.info(f'Parsed version from server jar {str(jar_path)!r}: {server_jar_version}')
			self.__prev_snapshot = server_jar_version

	def on_server_start(self):
		self.__read_server_jar_version()

	def __thread_loop(self):
		self.__read_server_jar_version()
		while not self.__stop_event.is_set():
			try:
				self.__check_and_update()
			except _StopException:
				self.logger.warning('Check and update interrupted')
			except Exception:
				self.logger.exception('Check and update error')

			self.__stop_event.wait(self.config.check_interval)

	def __request_get(self, url: str, timeout: float, stream: bool) -> requests.Response:
		proxies = {}
		if self.config.http_proxy:
			proxies['http'] = self.config.http_proxy
		if self.config.https_proxy:
			proxies['https'] = self.config.https_proxy
		return requests.get(url, proxies=proxies if proxies else None, timeout=timeout, stream=stream)

	def __request_get_json(self, url: str) -> dict:
		rsp = self.__request_get(url, timeout=self.config.request_timeout, stream=False)
		try:
			rsp.raise_for_status()
		except Exception:
			self.logger.error(f'Bad HTTP status code {rsp.status_code}, rsp body {rsp.content}')
			raise
		return rsp.json()

	def __download_file_and_sha1(self, url: str, dst: Path, max_size: int) -> str:
		rsp = self.__request_get(url, timeout=self.config.request_timeout, stream=True)

		read_n = 0
		hasher = hashlib.sha1()
		with open(dst, 'wb') as f:
			for chunk in rsp.iter_content(chunk_size=16384):
				self.__check_for_stop()
				f.write(chunk)
				hasher.update(chunk)
				read_n += len(chunk)
				if read_n > max_size:
					raise ValueError(f'body too large, read {read_n}, max size {max_size}')
		return hasher.hexdigest()

	def __check_and_update(self):
		if self.server.is_server_startup():
			self.logger.debug('server is not running, skipped update check')

		# =========== Check update from mojang API ===========

		version_manifest = self.__request_get_json('https://launchermeta.mojang.com/mc/game/version_manifest.json')
		latest_snapshot = _ensure_type(version_manifest['latest']['snapshot'], str)
		if not re.fullmatch(r'[a-z0-9-.]+', latest_snapshot):
			self.logger.warning(f'unsupported snapshot version string {latest_snapshot!r}')
			return
		if self.__prev_snapshot is None:
			self.logger.info(f'Recorded current latest snapshot: {latest_snapshot}')
			self.__prev_snapshot = latest_snapshot
			return

		if self.__prev_snapshot == latest_snapshot:
			self.logger.debug(f'Latest snapshot unchanged, {latest_snapshot}')
			return
		for item in version_manifest.get('versions', []):
			if item['id'] == latest_snapshot:
				latest_snapshot_url: str = item['url']
				break
		else:
			self.logger.error(f'Failed to locate {latest_snapshot} in version manifest')
			return

		# =========== New snapshot found, download it ===========

		self.__check_for_stop()
		self.server.broadcast(f'Found new snapshot: {self.__prev_snapshot} -> {latest_snapshot}')

		self.logger.info(f'Manifest url for {latest_snapshot}: {latest_snapshot_url}')
		snapshot_manifest = self.__request_get_json(latest_snapshot_url)
		server_jar_url = _ensure_type(snapshot_manifest['downloads']['server']['url'], str)
		server_jar_sha1 = _ensure_type(snapshot_manifest['downloads']['server']['sha1'], str)
		server_jar_size = _ensure_type(snapshot_manifest['downloads']['server']['size'], int)

		jars_dir = Path(self.server.get_data_folder()) / 'jars'
		jars_dir.mkdir(exist_ok=True)
		jar_path = jars_dir / f'{latest_snapshot}.jar'

		self.__check_for_stop()
		need_download = True
		if jar_path.is_file():
			try:
				file_sha1 = self.__calc_file_sha1(jar_path)
			except OSError:
				self.logger.exception(f'Calc existing jar file {jar_path} sha1 failed, redownload')
			else:
				if file_sha1 == server_jar_sha1:
					self.logger.info(f'File {jar_path.name} is already downloaded')
					need_download = False
				else:
					self.logger.info(f'File {jar_path.name} sha1 mismatch, expected {server_jar_sha1}, actual {file_sha1}, redownload')

		if need_download:
			self.logger.info(f'Downloading {jar_path.name} from {server_jar_url}, jar size {server_jar_size}, SHA1 {server_jar_sha1}')
			jar_path_tmp = jar_path.parent / (jar_path.name + '.tmp')
			try:
				downloaded_sha1 = self.__download_file_and_sha1(server_jar_url, jar_path_tmp, max_size=server_jar_size + 10)
				if downloaded_sha1 != server_jar_sha1:
					self.logger.error(f'SHA1 check failed, expected {server_jar_sha1}, actual {downloaded_sha1}')
				shutil.move(jar_path_tmp, jar_path)
			except Exception:
				with contextlib.suppress(OSError):
					jar_path_tmp.unlink()
				raise

		# =========== Update the server ===========

		self.__check_for_stop()
		self.server.broadcast('Stopping the server for server jar update')
		self.server.stop()
		self.server.wait_for_start()

		self.logger.info('Replacing the server jar')
		shutil.copy(jar_path, self.config.server_jar_path)
		self.__prev_snapshot = latest_snapshot

		self.logger.info(f'Starting the server, enjoy the new snapshot {latest_snapshot}~')
		self.server.start()
