#!/usr/bin/python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-


# plugin module name: plugins.wvpn_*
# config file: ${ETC}/cascade-vpn.json
# only allow one plugin be loaded
class PluginTemplateCascadeVpn:

    def init2(self, cfg, tmpDir, upCallback, downCallback):
        # upCallback:
        #   is_connected() should return True in upCallback().
        #   exception raised by upCallback() would make the plugin bring down the connection.
        # downCallback:
        #   is_connected() should return False in downCallback().
        #   no exception is allowed in downCallback().
        assert False

    def start(self):
        assert False

    def stop(self):
        assert False

    def disconnect(self):
        assert False

    def is_connected(self):
        assert False

    def get_local_ip(self):
        assert False

    def get_remote_ip(self):
        assert False

    def get_netmask(self):
        assert False

    def get_interface(self):
        assert False
