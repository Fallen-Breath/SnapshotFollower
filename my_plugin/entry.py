from mcdreforged.api.all import *


def on_load(server: PluginServerInterface, old):
	server.logger.info(server.tr('my_plugin.a_message'))
