from typing import Dict, Optional

from mcdreforged.api.all import Serializable


class WebHookConfig(Serializable):
	enabled: bool = True
	use_http_proxy: bool = False
	url: str = 'http://127.0.0.1:8080/example/path'
	headers: Dict[str, str] = {}
	body: str = 'Server has been updated to {{version}}'


class Config(Serializable):
	enabled: bool = True

	check_interval: float = 60
	server_jar_path: str = 'server/server.jar'
	keep_downloaded_jar: bool = True

	http_proxy: Optional[str] = None
	https_proxy: Optional[str] = None
	request_timeout: float = 10

	webhook: WebHookConfig = WebHookConfig()
