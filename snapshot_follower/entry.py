from mcdreforged.api.all import *


def on_load(server: PluginServerInterface, old):
	server.logger.info(server.tr('snapshot_follower.a_message'))

