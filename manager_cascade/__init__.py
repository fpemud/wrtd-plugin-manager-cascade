#!/usr/bin/python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-

import os
import pwd
import grp
import time
import socket
import logging
import netifaces
import ipaddress
import threading
import subprocess
from gi.repository import GLib
from gi.repository import GObject
from . import util


def get_plugin_list():
    return ["cascade"]


def get_plugin(name):
    if name == "cascade":
        return _PluginObject()
    else:
        assert False


class _PluginObject:

    def __init__(self, cfg, tmpDir, varDir, data):
        self.cascadeApiPort = 2221
        self.param = data
        self.logger = logging.getLogger(self.__module__ + "." + self.__class__.__name__)

        self.vpnPlugin = None
        try:
            cfgfile = os.path.join(self.param.etcDir, "cascade-vpn.json")
            if os.path.exists(cfgfile):
                cfgObj = None
                with open(cfgfile, "r") as f:
                    cfgObj = json.load(f)
                self.vpnPlugin = self.param.pluginHub.getPlugin("wvpn", cfgObj["plugin"])
                tdir = os.path.join(self.param.tmpDir, "wvpn-%s" % (cfgObj["plugin"]))
                os.mkdir(tdir)
                self.vpnPlugin.init2(cfgObj,
                                     tdir,
                                     lambda: self.param.managerCaller.call("on_wvpn_up"),
                                     lambda: self.param.managerCaller.call("on_wvpn_down"))
                self.logger.info("CASCADE-VPN activated, plugin: %s." % (cfgObj["plugin"]))
            else:
                self.logger.info("No CASCADE-VPN configured.")
        except:
            if self.vpnPlugin is not None:
                self.vpnPlugin = None
                self.logger.info("CASCADE-VPN deactivated.")

        # router info
        self.routerInfo = dict()
        self.routerInfo[self.param.uuid] = dict()
        self.routerInfo[self.param.uuid]["hostname"] = socket.gethostname()
        if self.vpnPlugin is not None:
            self.routerInfo[self.param.uuid]["cascade-vpn"] = dict()
        if self.param.wan_manager.wanConnPlugin is not None:
            self.routerInfo[self.param.uuid]["wan-prefix-list"] = []
        if True:
            self.routerInfo[self.param.uuid]["lan-prefix-list"] = []
            for bridge in [self.param.lan_manager.defaultBridge] + [x.get_bridge() for x in self.param.lan_manager.vpnsPluginList]:
                prefix = bridge.get_prefix()
                self.routerInfo[self.param.uuid]["lan-prefix-list"].append(prefix[0] + "/" + prefix[1])
        self.routerInfo[self.param.uuid]["client-list"] = dict()

        # routes dict
        self.routesDict = dict()            # dict<gateway-ip, dict<router-id, list<prefix>>>

        # client
        self.apiClient = None

        # servers
        self.apiServerList = []
        self.banUuidList = []

        # start CASCADE-API server for all the bridges
        for plugin in self.param.lan_manager.vpnsPluginList:
            self.apiServerList.append(_ApiServer(self, plugin.get_bridge()))
        self.logger.info("CASCADE-API servers started.")

    def dispose(self):
        for s in self.apiServerList:
            s.close()
        self.apiServerList = []

        if self.apiClient is not None:
            pass                # fixme

        if self.vpnPlugin is not None:
            self.vpnPlugin.stop()
            self.vpnPlugin = None
            self.logger.info("CASCADE-VPN deactivated.")

    def hasValidApiClient(self):
        return self.apiClient is not None and self.apiClient.bRegistered

    def getAllValidApiServerProcessors(self):
        return self.getAllValidApiServerProcessorsExcept(None)

    def getAllValidApiServerProcessorsExcept(self, sproc):
        ret = []
        for obj in self.apiServerList:
            for sproc2 in obj.sprocList:
                if sproc2.bRegistered and sproc2 != sproc:
                    ret.append(sproc2)
        return ret

    def getAllRouterApiServerProcessors(self):
        ret = []
        for obj in self.apiServerList:
            for sproc in obj.sprocList:
                if sproc.bRegistered and sproc.get_peer_uuid() is not None:
                    ret.append(sproc)
        return ret

    def on_wconn_up(self):
        self._wanPrefixListChange(self.param.wan_manager.wanConnPlugin.get_prefix_list())
        if self.vpnPlugin is not None:
            self.vpnPlugin.start()

    def on_wconn_down(self):
        if self.vpnPlugin is not None:
            self.vpnPlugin.stop()
        self._wanPrefixListChange([])

    def on_wvpn_up(self):
        # check vpn prefix
        if util.prefixListConflict(self.vpnPlugin.get_prefix_list(), self.param.wan_manager.wanConnPlugin.get_prefix_list()):
            raise Exception("cascade-VPN prefix duplicates with internet connection")
        if self.param.prefixPool.setExcludePrefixList("vpn", self.vpnPlugin.get_prefix_list()):
            os.kill(os.getpid(), signal.SIGHUP)
            raise Exception("bridge prefix duplicates with CASCADE-VPN connection, autofix it and restart")

        # process by myself
        self.routerInfo[self.param.uuid]["cascade-vpn"] = dict()
        self.routerInfo[self.param.uuid]["cascade-vpn"]["local-ip"] = self.vpnPlugin.get_local_ip()
        self.routerInfo[self.param.uuid]["cascade-vpn"]["remote-ip"] = self.vpnPlugin.get_remote_ip()
        assert self.apiClient is None
        self.apiClient = _ApiClient(self, self.vpnPlugin.get_remote_ip())

        # notify downstream
        data = dict()
        data[self.param.uuid] = dict()
        data[self.param.uuid]["cascade-vpn"] = self.routerInfo[self.param.uuid]["cascade-vpn"]
        for sproc in self.getAllValidApiServerProcessors():
            sproc.send_notification("router-cascade-vpn-change", data)

    def on_wvpn_down(self):
        # process by myself
        if self.apiClient is not None:
            self.apiClient.close()
            self.apiClient = None
        if "cascade-vpn" in self.routerInfo[self.param.uuid]:
            self.routerInfo[self.param.uuid]["cascade-vpn"] = dict()
        self.param.prefixPool.removeExcludePrefixList("vpn")

        # notify downstream
        data = dict()
        data[self.param.uuid] = dict()
        data[self.param.uuid]["cascade-vpn"] = self.routerInfo[self.param.uuid]["cascade-vpn"]
        for sproc in self.getAllValidApiServerProcessors():
            sproc.send_notification("router-cascade-vpn-change", data)

    def on_client_add(self, source_id, ip_data_dict):
        self._clientAddOrChange("add", source_id, ip_data_dict)

    def on_client_change(self, source_id, ip_data_dict):
        self._clientAddOrChange("change", source_id, ip_data_dict)

    def on_client_remove(self, source_id, ip_list):
        assert len(ip_list) > 0

        # process by myself
        for ip in ip_list:
            if ip in self.routerInfo[self.param.uuid]["client-list"]:
                del self.routerInfo[self.param.uuid]["client-list"][ip]
        for sproc in self.getAllValidApiServerProcessors():
            if sproc.get_peer_ip() in ip_list:
                sproc.close()

        # notify upstream
        if self._apiClientCanNotify():
            data = dict()
            data[self.param.uuid] = dict()
            data[self.param.uuid]["client-list"] = ip_list
            self.apiClient.send_notification("router-client-remove", data)

        # notify downstream
        data = dict()
        data[self.param.uuid] = dict()
        data[self.param.uuid]["client-list"] = ip_list
        for sproc in self.getAllValidApiServerProcessors():
            sproc.send_notification("router-client-remove", data)

    def on_cascade_upstream_up(self, api_client, data):
        self.banUuidList = []
        self.routesDict[api_client.get_peer_ip()] = dict()
        self.param.lan_manager.add_source("upstream-vpn")
        self.on_cascade_upstream_router_add(api_client, data["router-list"])

    def on_cascade_upstream_fail(self, api_client, excp):
        self.vpnPlugin.disconnect()

    def on_cascade_upstream_down(self, api_client):
        if api_client.routerInfo is not None and len(api_client.routerInfo) > 0:
            self.on_cascade_upstream_router_remove(api_client, api_client.routerInfo.keys())
        self.param.lan_manager.remove_source("upstream-vpn")
        if True:
            for router_id in api_client.get_router_info():
                self._removeRoutes(api_client.get_peer_ip(), router_id)
            del self.routesDict[api_client.get_peer_ip()]
        self.vpnPlugin.disconnect()

    def on_cascade_upstream_router_add(self, api_client, data):
        assert len(data) > 0

        # process by myself
        ret = False
        for router_id, item in data.items():
            tlist = _Helper.protocolPrefixListToPrefixList(item.get("wan-prefix-list", []))
            ret |= self.param.prefixPool.setExcludePrefixList("upstream-wan-%s" % (router_id), tlist)
            tlist = _Helper.protocolPrefixListToPrefixList(item.get("lan-prefix-list", []))
            ret |= self.param.prefixPool.setExcludePrefixList("upstream-lan-%s" % (router_id), tlist)
        if ret:
            os.kill(os.getpid(), signal.SIGHUP)
            raise Exception("prefix duplicates with upstream router %s, autofix it and restart" % (router_id))
        self._upstreamLanPrefixListChange(api_client, data)
        self._upstreamVpnHostRefresh(api_client)

        # notify downstream
        for sproc in self.getAllValidApiServerProcessors():
            sproc.send_notification("router-add", data)

    def on_cascade_upstream_router_remove(self, api_client, data):
        assert len(data) > 0

        # process by myself
        self._upstreamVpnHostRefresh(api_client)
        for router_id in data:
            self.param.prefixPool.removeExcludePrefixList("upstream-lan-%s" % (router_id))
            self.param.prefixPool.removeExcludePrefixList("upstream-wan-%s" % (router_id))
            self._removeRoutes(api_client.get_peer_ip(), router_id)

        # notify downstream
        for sproc in self.getAllValidApiServerProcessors():
            sproc.send_notification("router-remove", data)

    def on_cascade_upstream_router_wan_prefix_list_change(self, api_client, data):
        ret = False
        for router_id, item in data.items():
            tlist = _Helper.protocolPrefixListToPrefixList(item["wan-prefix-list"])
            ret |= self.param.prefixPool.setExcludePrefixList("upstream-wan-%s" % (router_id), tlist)
        if ret:
            os.kill(os.getpid(), signal.SIGHUP)
            raise Exception("prefix duplicates with upstream router %s, autofix it and restart" % (router_id))

        # notify downstream
        for sproc in self.getAllValidApiServerProcessors():
            sproc.send_notification("wan-prefix-list-change", data)

    def on_cascade_upstream_router_lan_prefix_list_change(self, api_client, data):
        # process by myself
        ret = False
        for router_id, item in data.items():
            tlist = _Helper.protocolPrefixListToPrefixList(item["lan-prefix-list"])
            ret |= self.param.prefixPool.setExcludePrefixList("upstream-lan-%s" % (router_id), tlist)
        if ret:
            os.kill(os.getpid(), signal.SIGHUP)
            raise Exception("prefix duplicates with upstream router %s, autofix it and restart" % (router_id))
        self._upstreamLanPrefixListChange(api_client, data)

        # notify downstream
        for sproc in self.getAllValidApiServerProcessors():
            sproc.send_notification("lan-prefix-list-change", data)

    def on_cascade_upstream_router_client_add(self, api_client, data):
        # process by myself
        self._upstreamVpnHostRefresh(api_client)

        # notify downstream
        for sproc in self.getAllValidApiServerProcessors():
            sproc.send_notification("router-client-add", data)

    def on_cascade_upstream_router_client_change(self, api_client, data):
        # process by myself
        self._upstreamVpnHostRefresh(api_client)

        # notify downstream
        for sproc in self.getAllValidApiServerProcessors():
            sproc.send_notification("router-client-change", data)

    def on_cascade_upstream_router_client_remove(self, api_client, data):
        # process by myself
        self._upstreamVpnHostRefresh(api_client)

        # notify downstream
        for sproc in self.getAllValidApiServerProcessors():
            sproc.send_notification("router-client-remove", data)

    def on_cascade_downstream_up(self, sproc, data):
        self.routesDict[sproc.get_peer_ip()] = dict()
        if len(data["router-list"]) > 0:
            self.on_cascade_downstream_router_add(sproc, data["router-list"])

    def on_cascade_downstream_down(self, sproc):
        self.on_cascade_downstream_router_remove(sproc, list(sproc.get_router_info().keys()))
        del self.routesDict[sproc.get_peer_ip()]

    def on_cascade_downstream_router_add(self, sproc, data):
        # process by myself
        self._downstreamWanPrefixListCheck(data)
        for router_id, router_info in data.items():
            if "lan-prefix-list" in data[router_id]:
                self._updateRoutes(sproc.get_peer_ip(), router_id, data[router_id]["lan-prefix-list"])
            if "client-list" in router_info:
                self.param.lan_manager.add_source("downstream-" + router_id)
                self.param.lan_manager.add_client("downstream-" + router_id, router_info["client-list"])

        # notify upstream and other downstream
        if self.hasValidApiClient():
            self.apiClient.send_notification("router-add", data)
        for obj in self.getAllValidApiServerProcessorsExcept(sproc):
            obj.send_notification("router-add", data)

    def on_cascade_downstream_router_remove(self, sproc, data):
        # process by myself
        for router_id in data:
            self.param.lan_manager.remove_source("downstream-" + router_id)
            self._removeRoutes(sproc.get_peer_ip(), router_id)
            self.param.prefixPool.removeExcludePrefixList("downstream-wan-%s" % (router_id))

        # notify upstream and other downstream
        if self.hasValidApiClient():
            self.apiClient.send_notification("router-remove", data)
        for obj in self.getAllValidApiServerProcessorsExcept(sproc):
            obj.send_notification("router-remove", data)

    def on_cascade_downstream_router_wan_prefix_list_change(self, sproc, data):
        # process by myself
        self._downstreamWanPrefixListCheck(data)

        # notify upstream and other downstream
        if self.hasValidApiClient():
            self.apiClient.send_notification("router-wan-prefix-list-change", data)
        for obj in self.getAllValidApiServerProcessorsExcept(sproc):
            obj.send_notification("router-wan-prefix-list-change", data)

    def on_cascade_downstream_router_lan_prefix_list_change(self, sproc, data):
        # process by myself
        for router_id in data:
            self._updateRoutes(sproc.get_peer_ip(), router_id, data[router_id]["lan-prefix-list"])

        # notify upstream and other downstream
        if self.hasValidApiClient():
            self.apiClient.send_notification("router-lan-prefix-list-change", data)
        for obj in self.getAllValidApiServerProcessorsExcept(sproc):
            obj.send_notification("router-lan-prefix-list-change", data)

    def on_cascade_downstream_router_client_add(self, sproc, data):
        # process by myself
        for router_id, router_info in data.items():
            self.param.lan_manager.add_client("downstream-" + router_id, router_info["client-list"])

        # notify upstream and other downstream
        if self.hasValidApiClient():
            self.apiClient.send_notification("router-client-add", data)
        for obj in self.getAllValidApiServerProcessorsExcept(sproc):
            obj.send_notification("router-client-add", data)

    def on_cascade_downstream_router_client_change(self, sproc, data):
        # process by myself
        for router_id, router_info in data.items():
            self.param.lan_manager.change_client("downstream-" + router_id, router_info["client-list"])

        # notify upstream and other downstream
        if self.hasValidApiClient():
            self.apiClient.send_notification("router-client-change", data)
        for obj in self.getAllValidApiServerProcessorsExcept(sproc):
            obj.send_notification("router-client-change", data)

    def on_cascade_downstream_router_client_remove(self, sproc, data):
        # process by myself
        for router_id, router_info in data.items():
            self.param.lan_manager.remove_client("downstream-" + router_id, router_info["client-list"])

        # notify upstream and other downstream
        if self.hasValidApiClient():
            self.apiClient.send_notification("router-client-remove", data)
        for obj in self.getAllValidApiServerProcessorsExcept(sproc):
            obj.send_notification("router-client-remove", data)

    def _clientAddOrChange(self, type, source_id, ip_data_dict):
        assert len(ip_data_dict) > 0

        # process by myself
        self.routerInfo[self.param.uuid]["client-list"].update(ip_data_dict)

        # notify upstream
        if self._apiClientCanNotify():
            data = dict()
            data[self.param.uuid] = dict()
            data[self.param.uuid]["client-list"] = ip_data_dict
            self.apiClient.send_notification("router-client-%s" % (type), data)

        # notify downstream
        data = dict()
        data[self.param.uuid] = dict()
        data[self.param.uuid]["client-list"] = ip_data_dict
        for sproc in self.getAllValidApiServerProcessors():
            sproc.send_notification("router-client-%s" % (type), data)

    def _wanPrefixListChange(self, prefixList):
        prefixList = _Helper.prefixListToProtocolPrefixList(prefixList)

        # process by myself
        self.routerInfo[self.param.uuid]["wan-prefix-list"] = prefixList

        # notify upstream & downstream
        data = dict()
        data[self.param.uuid] = dict()
        data[self.param.uuid]["wan-prefix-list"] = prefixList
        if self._apiClientCanNotify():
            self.apiClient.send_notification("router-wan-prefix-list-change", data)
        for sproc in self.getAllValidApiServerProcessors():
            sproc.send_notification("router-wan-prefix-list-change", data)

    def _upstreamLanPrefixListChange(self, api_client, data):
        for router_id in data:
            if "lan-prefix-list" not in data[router_id]:
                continue                # called by on_cascade_upstream_router_add()
            if router_id == api_client.get_peer_uuid():
                tlist = list(data[router_id]["lan-prefix-list"])
                for prefix in self.param.wan_manager.vpnPlugin.get_prefix_list():
                    tlist.remove(prefix[0] + "/" + prefix[1])
            else:
                tlist = data[router_id]["lan-prefix-list"]
            self._updateRoutes(api_client.get_peer_ip(), router_id, tlist)

    def _downstreamWanPrefixListCheck(self, data):
        # check downstream wan-prefix and restart if neccessary
        show_router_id = None
        for router_id, item in data.items():
            if "wan-prefix-list" not in item:
                continue        # used when called by on_cascade_downstream_router_add()
            tlist = _Helper.protocolPrefixListToPrefixList(item["wan-prefix-list"])
            if self.param.prefixPool.setExcludePrefixList("downstream-wan-%s" % (router_id), tlist):
                show_router_id = router_id
        if show_router_id is not None:
            os.kill(os.getpid(), signal.SIGHUP)
            raise Exception("prefix duplicates with downstream router %s, autofix it and restart" % (show_router_id))

    def _upstreamVpnHostRefresh(self, api_client):
        # we need to differentiate upstream router and other client, so we do refresh instead of add/change/remove
        ipDataDict = dict()

        # add upstream routers into ipDataDict
        upstreamRouterLocalIpList = []
        if self.hasValidApiClient():
            curUpstreamId = api_client.get_peer_uuid()
            curUpstreamIp = api_client.get_peer_ip()
            curUpstreamLocalIp = self.param.wan_manager.vpnPlugin.get_local_ip()
            while True:
                data = api_client.get_router_info()[curUpstreamId]

                ipDataDict[curUpstreamIp] = dict()
                if "hostname" in data:
                    ipDataDict[curUpstreamIp]["hostname"] = data["hostname"]
                upstreamRouterLocalIpList.append(curUpstreamLocalIp)

                if "parent" not in data:
                    break
                curUpstreamId = data["parent"]
                curUpstreamIp = data["cascade-vpn"]["remote-ip"]
                curUpstreamLocalIp = data["cascade-vpn"]["local-ip"]

        # add all clients into ipDataDict
        for router in api_client.get_router_info().values():
            if "client-list" in router:
                for ip, data in router["client-list"].items():
                    if ip in upstreamRouterLocalIpList:
                        continue
                    ipDataDict[ip] = data

        # refresh to all bridges
        self.param.lan_manager.refresh_client("upstream-vpn")

    def _apiClientCanNotify(self):
        return self.apiClient is not None and self.apiClient.bConnected

    def _updateRoutes(self, gateway_ip, router_id, prefix_list):
        if router_id not in self.routesDict[gateway_ip]:
            self.routesDict[gateway_ip][router_id] = []
        with pyroute2.IPRoute() as ipp:
            # remove routes
            tlist = list(self.routesDict[gateway_ip][router_id])
            for prefix in tlist:
                if prefix not in prefix_list:
                    ipp.route("del", dst=self.__prefixConvert(prefix))
                    self.routesDict[gateway_ip][router_id].remove(prefix)
            # add routes
            for prefix in prefix_list:
                if prefix not in self.routesDict[gateway_ip][router_id]:
                    ipp.route("add", dst=self.__prefixConvert(prefix), gateway=gateway_ip)
                    self.routesDict[gateway_ip][router_id].append(prefix)

    def _removeRoutes(self, gateway_ip, router_id):
        if router_id in self.routesDict[gateway_ip]:
            with pyroute2.IPRoute() as ipp:
                for prefix in self.routesDict[gateway_ip][router_id]:
                    ipp.route("del", dst=self.__prefixConvert(prefix))
                del self.routesDict[gateway_ip][router_id]

    def __prefixConvert(self, prefix):
        tl = prefix.split("/")
        return tl[0] + "/" + str(util.ipMaskToLen(tl[1]))


class _ApiClient(JsonApiEndPoint):

    # no exception is allowed in on_cascade_upstream_fail(),  on_cascade_upstream_error(),  on_cascade_upstream_down().
    # on_cascade_upstream_fail() would be called if there's error before client is registered.
    # on_cascade_upstream_error() would be called if there's error after client is registered.

    def __init__(self, pObj, remote_ip):
        super().__init__()
        self.pObj = pObj
        self.remoteIp = remote_ip

        sc = Gio.SocketClient.new()
        sc.set_family(Gio.SocketFamily.IPV4)
        sc.set_protocol(Gio.SocketProtocol.TCP)

        self.logger.info("Establishing CASCADE-API connection.")
        self.peerUuid = None
        self.routerInfo = None
        self.bConnected = False
        self.bRegistered = False
        sc.connect_to_host_async(self.remoteIp, self.pObj.cascadeApiPort, None, self._on_connect)

    def get_peer_uuid(self):
        return self.peerUuid

    def get_peer_ip(self):
        return self.remoteIp

    def get_router_info(self):
        return self.routerInfo

    def _on_connect(self, source_object, res):
        try:
            conn = source_object.connect_to_host_finish(res)
            super().set_iostream_and_start(conn)

            # send register command
            data = dict()
            data["my-id"] = self.pObj.param.uuid
            data["router-list"] = dict()
            if True:
                data["router-list"].update(self.pObj.routerInfo)
                for sproc in self.pObj.getAllRouterApiServerProcessors():
                    data["router-list"].update(sproc.get_router_info())
                    data["router-list"][sproc.get_peer_uuid()]["parent"] = self.pObj.param.uuid
            super().exec_command("register", data, self._on_register_return, self._on_register_error)

            self.bConnected = True
        except Exception as e:
            self.logger.error("Failed to establish CASCADE-API connection", exc_info=True)   # fixme
            self.pObj.param.managerCaller.call("on_cascade_upstream_fail", self, e)
            self.close()

    def _on_register_return(self, data):
        self.peerUuid = data["my-id"]
        self.routerInfo = data["router-list"]
        self.bRegistered = True
        self.logger.info("CASCADE-API connection established.")
        _Helper.logRouterAdd(self.routerInfo, self.logger)
        self.pObj.param.managerCaller.call("on_cascade_upstream_up", self, data)

    def _on_register_error(self, reason):
        m = re.match("UUID (.*) duplicate", reason)
        if m is not None:
            for sproc in self.pObj.getAllRouterApiServerProcessors():
                if m.group(1) in sproc.get_router_info():
                    self.pObj.banUuidList.append(m.group(1))
                    sproc.close()
        raise Exception(reason)

    def on_error(self, excp):
        if not self.bRegistered:
            self.logger.error("Failed to establish CASCADE-API connection.", exc_info=True)      # fixme
            self.pObj.param.managerCaller.call("on_cascade_upstream_fail", self, excp)
        else:
            self.logger.error("CASCADE-API connection disconnected with error.", exc_info=True)  # fixme
            self.pObj.param.managerCaller.call("on_cascade_upstream_error", self, excp)

    def on_close(self):
        if not self.bRegistered:
            pass
        else:
            self.pObj.param.managerCaller.call("on_cascade_upstream_down", self)
            _Helper.logRouterRemoveAll(self.routerInfo, self.logger)

    def on_notification_router_add(self, data):
        assert self.bRegistered

        ret = _Helper.upstreamRouterIdDuplicityCheck(self.pObj.param, data)
        if ret is not None:
            uuid, sproc = ret
            if sproc is not None:
                self.pObj.banUuidList.append(uuid)
                sproc.close()
            raise Exception("UUID %s duplicate" % (uuid))

        self.routerInfo.update(data)
        _Helper.logRouterAdd(data, self.logger)
        self.pObj.param.managerCaller.call("on_cascade_upstream_router_add", self, data)

    def on_notification_router_remove(self, data):
        assert self.bRegistered
        self.pObj.param.managerCaller.call("on_cascade_upstream_router_remove", self, data)
        _Helper.logRouterRemove(data, self.routerInfo, self.logger)
        for router_id in data:
            del self.routerInfo[router_id]

    def on_notification_router_cascade_vpn_change(self, data):
        assert self.bRegistered
        for router_id, item in data.items():
            self.routerInfo[router_id]["cascade-vpn"] = item["cascade-vpn"]
        self.pObj.param.managerCaller.call("on_cascade_upstream_router_cascade_vpn_change", self, data)

    def on_notification_router_wan_prefix_list_change(self, data):
        assert self.bRegistered
        for router_id, item in data.items():
            self.routerInfo[router_id]["wan-prefix-list"] = item["wan-prefix-list"]
        self.pObj.param.managerCaller.call("on_cascade_upstream_router_wan_prefix_list_change", self, data)

    def on_notification_router_lan_prefix_list_change(self, data):
        assert self.bRegistered
        for router_id, item in data.items():
            self.routerInfo[router_id]["lan-prefix-list"] = item["lan-prefix-list"]
        self.pObj.param.managerCaller.call("on_cascade_upstream_router_lan_prefix_list_change", self, data)

    def on_notification_router_client_add(self, data):
        assert self.bRegistered
        for router_id, item in data.items():
            self.routerInfo[router_id]["client-list"].update(item["client-list"])
        _Helper.logRouterClientAdd(data, self.logger)
        self.pObj.param.managerCaller.call("on_cascade_upstream_router_client_add", self, data)

    def on_notification_router_client_change(self, data):
        assert self.bRegistered
        for router_id, item in data.items():
            self.routerInfo[router_id]["client-list"].update(item["client-list"])
        # no log needed for client change
        self.pObj.param.managerCaller.call("on_cascade_upstream_router_client_change", self, data)

    def on_notification_router_client_remove(self, data):
        assert self.bRegistered
        self.pObj.param.managerCaller.call("on_cascade_upstream_router_client_remove", self, data)
        _Helper.logRouterClientRemove(data, self.routerInfo, self.logger)
        for router_id, item in data.items():
            for ip in item["client-list"]:
                del self.routerInfo[router_id]["client-list"][ip]


class _ApiServer:

    def __init__(self, pObj, bridge):
        self.pObj = pObj

        self.serverListener = Gio.SocketListener.new()
        addr = Gio.InetSocketAddress.new_from_string(util.bridgeGetIp(bridge), self.pObj.cascadeApiPort)
        self.serverListener.add_address(addr, Gio.SocketType.STREAM, Gio.SocketProtocol.TCP)
        self.serverListener.accept_async(None, self._on_accept)

        self.sprocList = []

    def close(self):
        for sproc in self.sprocList:
            sproc.close()
        self.serverListener.close()

    def _on_accept(self, source_object, res):
        conn, dummy = source_object.accept_finish(res)
        sproc = _ApiServerProcessor(self.pObj, self, conn)
        self.sprocList.append(sproc)
        self.logger.info("CASCADE-API client %s accepted." % (conn.get_remote_address().get_address().to_string()))
        self.serverListener.accept_async(None, self._on_accept)


class _ApiServerProcessor(JsonApiEndPoint):

    def __init__(self, pObj, serverObj, conn):
        super().__init__()
        self.pObj = pObj
        self.serverObj = serverObj
        self.conn = conn
        self.peerUuid = None
        self.routerInfo = None
        self.bRegistered = False
        super().set_iostream_and_start(self.conn)

    def get_peer_uuid(self):
        return self.peerUuid

    def get_peer_ip(self):
        return self.conn.get_remote_address().get_address().to_string()

    def get_router_info(self):
        return self.routerInfo

    def on_error(self, e):
        self.logger.error("debugXXXXXXXXXXXX", exc_info=True)            # fixme

    def on_close(self):
        if self.bRegistered:
            self.pObj.param.managerCaller.call("on_cascade_downstream_down", self)
            if self.peerUuid is not None:
                _Helper.logRouterRemoveAll(self.routerInfo, self.logger)
        self.routerInfo = None
        self.peerUuid = None
        self.logger.info("CASCADE-API client %s disconnected." % (self.get_peer_ip()))
        self.serverObj.sprocList.remove(self)

    def on_command_register(self, data, return_callback, error_callback):
        # check data
        if "my-id" in data:
            uuid = _Helper.downStreamRouterIdDuplicityCheck(self.pObj.param, data["router-list"])
            if uuid is not None:
                self.logger.error("CASCADE-API client %s rejected, UUID %s duplicate." % (self.get_peer_ip(), uuid))
                error_callback("UUID %s duplicate" % (uuid))
                # no need to actively close connection, client would close it
                return

        # save data
        if "my-id" in data:
            self.peerUuid = data["my-id"]
            self.routerInfo = data["router-list"]

        # send reply
        data2 = dict()
        data2["my-id"] = self.pObj.param.uuid
        data2["router-list"] = dict()
        if True:
            data2["router-list"].update(self.pObj.routerInfo)
            if self.pObj.hasValidApiClient():
                data2["router-list"][self.pObj.param.uuid]["parent"] = self.pObj.apiClient.peerUuid
                data2["router-list"].update(self.pObj.apiClient.routerInfo)
            for sproc in self.pObj.getAllRouterApiServerProcessors():
                data2["router-list"].update(sproc.routerInfo)
                data2["router-list"][sproc.peerUuid]["parent"] = self.pObj.param.uuid
        return_callback(data2)

        # registered
        self.bRegistered = True
        self.logger.info("CASCADE-API client %s registered." % (self.get_peer_ip()))
        if self.peerUuid is not None:
            _Helper.logRouterAdd(self.routerInfo, self.logger)
        self.pObj.param.managerCaller.call("on_cascade_downstream_up", self, data)

    def on_notification_router_add(self, data):
        assert self.bRegistered and self.peerUuid is not None

        uuid = _Helper.downStreamRouterIdDuplicityCheck(self.pObj.param, data)
        if uuid is not None:
            raise Exception("UUID %s duplicate" % (uuid))

        self.routerInfo.update(data)
        _Helper.logRouterAdd(data, self.logger)
        self.pObj.param.managerCaller.call("on_cascade_downstream_router_add", self, data)

    def on_notification_router_remove(self, data):
        assert self.bRegistered and self.peerUuid is not None

        self.pObj.param.managerCaller.call("on_cascade_downstream_router_remove", self, data)
        _Helper.logRouterRemove(data, self.routerInfo, self.logger)
        for router_id in data:
            del self.routerInfo[router_id]

    def on_notification_router_wan_prefix_list_change(self, data):
        assert self.bRegistered and self.peerUuid is not None

        for router_id, item in data.items():
            self.routerInfo[router_id]["wan-prefix-list"] = item["wan-prefix-list"]
        self.pObj.param.managerCaller.call("on_cascade_downstream_router_wan_prefix_list_change", self, data)

    def on_notification_router_lan_prefix_list_change(self, data):
        assert self.bRegistered and self.peerUuid is not None

        for router_id, item in data.items():
            self.routerInfo[router_id]["lan-prefix-list"] = item["lan-prefix-list"]
        self.pObj.param.managerCaller.call("on_cascade_downstream_router_lan_prefix_list_change", self, data)

    def on_notification_router_client_add(self, data):
        assert self.bRegistered and self.peerUuid is not None

        for router_id, item in data.items():
            self.routerInfo[router_id]["client-list"].update(item["client-list"])
        _Helper.logRouterClientAdd(data, self.logger)
        self.pObj.param.managerCaller.call("on_cascade_downstream_router_client_add", self, data)

    def on_notification_router_client_change(self, data):
        assert self.bRegistered and self.peerUuid is not None

        for router_id, item in data.items():
            self.routerInfo[router_id]["client-list"].update(item["client-list"])
        # no log needed for client change
        self.pObj.param.managerCaller.call("on_cascade_downstream_router_client_change", self, data)

    def on_notification_router_client_remove(self, data):
        assert self.bRegistered and self.peerUuid is not None

        self.pObj.param.managerCaller.call("on_cascade_downstream_router_client_remove", self, data)
        _Helper.logRouterClientRemove(data, self.routerInfo, self.logger)
        for router_id, item in data.items():
            for ip in item["client-list"]:
                del self.routerInfo[router_id]["client-list"][ip]


class _Helper:

    @staticmethod
    def prefixListToProtocolPrefixList(prefixList):
        ret = []
        for prefix in prefixList:
            ret.append(prefix[0] + "/" + prefix[1])
        return ret

    @staticmethod
    def protocolPrefixListToPrefixList(protocolPrefixList):
        ret = []
        for prefix in protocolPrefixList:
            tlist = prefix.split("/")
            ret.append((tlist[0], tlist[1]))
        return ret

    @staticmethod
    def upstreamRouterIdDuplicityCheck(param, routerInfo):
        if param.uuid in routerInfo:
            return (param.uuid, None)
        for sproc in param.cascadeManager.getAllRouterApiServerProcessors():
            ret = set(sproc.get_router_info().keys()) & set(routerInfo.keys())
            ret = list(ret)
            if len(ret) > 0:
                return (ret[0], sproc)
        return None

    @staticmethod
    def downStreamRouterIdDuplicityCheck(param, routerInfo):
        if param.uuid in routerInfo:
            return param.uuid
        if param.cascadeManager.hasValidApiClient():
            ret = set(param.cascadeManager.apiClient.get_router_info()) & set(routerInfo.keys())
            ret = list(ret)
            if len(ret) > 0:
                return ret[0]
        for sproc in param.cascadeManager.getAllRouterApiServerProcessors():
            ret = set(sproc.get_router_info().keys()) & set(routerInfo.keys())
            ret = list(ret)
            if len(ret) > 0:
                return ret[0]
        return None

    @staticmethod
    def logRouterAdd(data, logger):
        for router_id, item in data.items():
            if "hostname" in data:
                logger.info("Router %s(UUID:%s) appeared." % (item["hostname"], router_id))
            else:
                logger.info("Router %s appeared." % (router_id))
            if "client-list" in item:
                for ip, data2 in item["client-list"].items():
                    if "hostname" in data2:
                        logger.info("Client %s(IP:%s) appeared." % (data2["hostname"], ip))
                    else:
                        logger.info("Client %s appeared." % (ip))

    @staticmethod
    def logRouterRemove(data, router_info, logger):
        for router_id in data:
            data2 = router_info[router_id]
            if "client-list" in data2:
                o = data2["client-list"]
                for ip in o.keys():
                    if "hostname" in o[ip]:
                        logger.info("Client %s(IP:%s) disappeared." % (o[ip]["hostname"], ip))
                    else:
                        logger.info("Client %s disappeared." % (ip))
            if "hostname" in data2:
                logger.info("Router %s(UUID:%s) disappeared." % (data2["hostname"], router_id))
            else:
                logger.info("Router %s disappeared." % (router_id))

    @staticmethod
    def logRouterRemoveAll(router_info, logger):
        _Helper.logRouterRemove(list(router_info.keys()), router_info, logger)

    @staticmethod
    def logRouterClientAdd(data, logger):
        for router_id, item in data.items():
            for ip, data2 in item["client-list"].items():
                if "hostname" in data2:
                    logger.info("Client %s(IP:%s) appeared." % (data2["hostname"], ip))
                else:
                    logger.info("Client %s appeared." % (ip))

    @staticmethod
    def logRouterClientRemove(data, router_info, logger):
        for router_id, item in data.items():
            o = router_info[router_id]["client-list"]
            for ip in item["client-list"]:
                if "hostname" in o[ip]:
                    logger.info("Client %s(IP:%s) disappeared." % (o[ip]["hostname"], ip))
                else:
                    logger.info("Client %s disappeared." % (ip))
