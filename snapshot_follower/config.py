from mcdreforged.api.all import Serializable


class Config(Serializable):
	enabled: bool = True
	check_interval: float = 60
	server_jar_path: str = 'server/server.jar'

	http_proxy: str = ''
	https_proxy: str = ''

	request_timeout: float = 10
