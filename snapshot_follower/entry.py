from typing import Optional

from mcdreforged.api.all import *

from snapshot_follower.config import Config
from snapshot_follower.worker import SnapshotFollowerWorker

worker: Optional[SnapshotFollowerWorker] = None


def on_load(server: PluginServerInterface, old):
	config = server.load_config_simple(target_class=Config)
	if not config.enabled:
		server.logger.warning('{} is disabled by config'.format(server.get_self_metadata().name))
		return

	global worker
	worker = SnapshotFollowerWorker(server, config)
	worker.start()


def on_unload(server: PluginServerInterface):
	if worker is not None:
		worker.stop()


def on_server_start(server: PluginServerInterface):
	if worker is not None:
		worker.on_server_start()
