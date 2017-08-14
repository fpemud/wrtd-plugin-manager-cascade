#!/usr/bin/python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-

import os
import re
import json
import signal
import socket
import logging
import pyroute2
import ipaddress
import msghole
from gi.repository import Gio
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

    @property
    def init_after(self):
        return []

    def init2(self, cfg, tmpDir, varDir, data):
        self.param = data
        self.logger = logging.getLogger(self.__module__ + "." + self.__class__.__name__)

        self.vpnPlugin = None

        self.router_info = dict()

        self.routesDict = dict()            # dict<gateway-ip, dict<router-id, list<prefix>>>

        self.apiPort = 2221
        self.apiClient = None
        self.apiServer = None

        self.banUuidList = []

        try:
            # cascade-vpn plugin
            cfgfile = os.path.join(self.param.etcDir, "cascade-vpn.json")
            if os.path.exists(cfgfile):
                cfgObj = None
                with open(cfgfile, "r") as f:
                    cfgObj = json.load(f)
                self.vpnPlugin = self.param.plugin_hub.getPlugin("wvpn", cfgObj["plugin"])
                tdir = os.path.join(self.param.tmpDir, "wvpn-%s" % (cfgObj["plugin"]))
                os.mkdir(tdir)
                self.vpnPlugin.init2(cfgObj,
                                     tdir,
                                     lambda: self.param.manager_caller.call("on_wvpn_up"),
                                     lambda: self.param.manager_caller.call("on_wvpn_down"))
                self.logger.info("CASCADE-VPN activated, plugin: %s." % (cfgObj["plugin"]))
            else:
                self.logger.info("No CASCADE-VPN configured.")

            # router info
            self.router_info[self.param.uuid] = dict()
            self.router_info[self.param.uuid]["hostname"] = socket.gethostname()
            if self.vpnPlugin is not None:
                self.router_info[self.param.uuid]["cascade-vpn"] = dict()
            if self.param.managers["wan"].wanConnPlugin is not None:
                self.router_info[self.param.uuid]["wan-connection"] = dict()
            if True:
                self.router_info[self.param.uuid]["lan-prefix-list"] = []
                for bridge in [self.param.managers["lan"].defaultBridge] + [x.get_bridge() for x in self.param.managers["lan"].vpnsPluginList]:
                    prefix = bridge.get_prefix()
                    self.router_info[self.param.uuid]["lan-prefix-list"].append(prefix[0] + "/" + prefix[1])
            self.router_info[self.param.uuid]["client-list"] = dict()

            # api server
            if len(self.param.managers["lan"].vpnsPluginList) > 0:
                self.apiServer = _ApiServer(self)
                self.logger.info("CASCADE-API server started.")
        except:
            self.dispose()
            raise

    def dispose(self):
        if self.apiServer is not None:
            self.apiServer.close()
            self.logger.info("CASCADE-API server stopped.")
        if self.apiClient is not None:
            self.apiClient.close()
        if self.vpnPlugin is not None:
            self.vpnPlugin.stop()
            self.logger.info("CASCADE-VPN deactivated.")

    def get_router_info(self):
        ret = dict()

        if self.vpnPlugin is not None:
            ret["wvpn-plugin"] = dict()
            ret["wvpn-plugin"]["name"] = self.vpnPlugin.full_name
            if self.vpnPlugin.is_connected():
                ret["wvpn-plugin"]["is-connected"] = True
            else:
                ret["wvpn-plugin"]["is-connected"] = False

        ret["cascade"] = dict()
        if True:
            ret["cascade"]["my-id"] = self.param.uuid
            ret["cascade"]["router-list"] = dict()
            ret["cascade"]["router-list"].update(self.router_info)
            if self._apiClientRegistered():
                ret["cascade"]["router-list"][self.param.uuid]["parent"] = self.apiClient.peer_uuid
                ret["cascade"]["router-list"].update(self.apiClient.router_info)
            for sproc in self._getApiServerProcessors():
                ret["cascade"]["router-list"].update(sproc.router_info)
                ret["cascade"]["router-list"][sproc.peer_uuid]["parent"] = self.param.uuid

        return ret

    def on_wan_conn_up(self):
        self._wanConnectionChange()
        if self.vpnPlugin is not None:
            self.vpnPlugin.start()

    def on_wan_conn_down(self):
        if self.vpnPlugin is not None:
            self.vpnPlugin.stop()
        self._wanConnectionChange()

    def on_wan_ipcheck_complete(self, isIpPublic):
        self._wanConnectionChange()

    def on_wvpn_up(self):
        # check vpn prefix
        vpnPrefixList = [util.ipMaskToPrefix(self.vpnPlugin.get_local_ip(), self.vpnPlugin.get_netmask())]
        wanPrefixList = [util.ipMaskToPrefix(self.param.managers["wan"].wanConnPlugin.get_ip(), self.param.managers["wan"].wanConnPlugin.get_netmask())] + self.param.managers["wan"].wanConnPlugin.get_extra_prefix_list()
        if util.prefixListConflict(vpnPrefixList, wanPrefixList):
            raise Exception("cascade-VPN prefix duplicates with internet connection")
        if self.param.prefix_pool.setExcludePrefixList("vpn", vpnPrefixList):
            os.kill(os.getpid(), signal.SIGHUP)
            raise Exception("bridge prefix duplicates with CASCADE-VPN connection, autofix it and restart")

        # process by myself
        self.router_info[self.param.uuid]["cascade-vpn"] = dict()
        self.router_info[self.param.uuid]["cascade-vpn"]["local-ip"] = self.vpnPlugin.get_local_ip()
        self.router_info[self.param.uuid]["cascade-vpn"]["remote-ip"] = self.vpnPlugin.get_remote_ip()
        assert self.apiClient is None
        self.apiClient = _ApiClient(self, self.vpnPlugin.get_remote_ip())

        # notify downstream
        data = dict()
        data[self.param.uuid] = dict()
        data[self.param.uuid]["cascade-vpn"] = self.router_info[self.param.uuid]["cascade-vpn"]
        for sproc in self._getApiServerProcessors():
            sproc.send_notification("router-cascade-vpn-change", data)

    def on_wvpn_down(self):
        # process by myself
        if self.apiClient is not None:
            self.apiClient.close()
            self.apiClient = None
        if "cascade-vpn" in self.router_info[self.param.uuid]:
            self.router_info[self.param.uuid]["cascade-vpn"] = dict()
        self.param.prefix_pool.removeExcludePrefixList("vpn")

        # notify downstream
        data = dict()
        data[self.param.uuid] = dict()
        data[self.param.uuid]["cascade-vpn"] = self.router_info[self.param.uuid]["cascade-vpn"]
        for sproc in self._getApiServerProcessors():
            sproc.send_notification("router-cascade-vpn-change", data)

    def on_client_add(self, source_id, ip_data_dict):
        assert len(ip_data_dict) > 0
        self._clientAddOrChange("add", source_id, ip_data_dict)

    def on_client_change(self, source_id, ip_data_dict):
        assert len(ip_data_dict) > 0
        self._clientAddOrChange("change", source_id, ip_data_dict)

    def on_client_remove(self, source_id, ip_list):
        assert len(ip_list) > 0

        # process by myself
        for ip in ip_list:
            if ip in self.router_info[self.param.uuid]["client-list"]:
                del self.router_info[self.param.uuid]["client-list"][ip]
        for sproc in self._getApiServerProcessors():
            if sproc.peer_ip in ip_list:
                sproc.close()

        # notify upstream & downstream
        data = {
            self.param.uuid: {
                "client-list": ip_list,
            },
        }
        if self._apiClientConnected():
            self.apiClient.send_notification("router-client-remove", data)
        for sproc in self._getApiServerProcessors():
            sproc.send_notification("router-client-remove", data)

    def on_cascade_upstream_up(self, api_client, data):
        self.banUuidList = []
        self.routesDict[api_client.peer_ip] = dict()
        self._bridgeAddSource("upstream-vpn")
        self.on_cascade_upstream_router_add(api_client, data["router-list"])

    def on_cascade_upstream_fail(self, api_client, excp):
        self.vpnPlugin.disconnect()

    def on_cascade_upstream_down(self, api_client):
        if api_client.router_info is not None and len(api_client.router_info) > 0:
            self.on_cascade_upstream_router_remove(api_client, api_client.router_info.keys())
        self._bridgeRemoveSource("upstream-vpn")
        if True:
            for router_id in api_client.router_info:
                self._removeRoutes(api_client.peer_ip, router_id)
            del self.routesDict[api_client.peer_ip]
        self.vpnPlugin.disconnect()

    def on_cascade_upstream_router_add(self, api_client, data):
        assert len(data) > 0

        # process by myself
        ret = False
        for router_id, item in data.items():
            tlist = _Helper.protocolWanConnectionToPrefixList(item.get("wan-connection", dict()))
            ret |= self.param.prefix_pool.setExcludePrefixList("upstream-wan-%s" % (router_id), tlist)
            tlist = _Helper.protocolPrefixListToPrefixList(item.get("lan-prefix-list", []))
            ret |= self.param.prefix_pool.setExcludePrefixList("upstream-lan-%s" % (router_id), tlist)
        if ret:
            os.kill(os.getpid(), signal.SIGHUP)
            raise Exception("prefix duplicates with upstream router %s, autofix it and restart" % (router_id))
        self._upstreamLanPrefixListChange(api_client, data)
        self._upstreamVpnHostRefresh(api_client)

        # notify downstream
        for sproc in self._getApiServerProcessors():
            sproc.send_notification("router-add", data)

    def on_cascade_upstream_router_remove(self, api_client, data):
        assert len(data) > 0

        # process by myself
        self._upstreamVpnHostRefresh(api_client)
        for router_id in data:
            self.param.prefix_pool.removeExcludePrefixList("upstream-lan-%s" % (router_id))
            self.param.prefix_pool.removeExcludePrefixList("upstream-wan-%s" % (router_id))
            self._removeRoutes(api_client.peer_ip, router_id)

        # notify downstream
        for sproc in self._getApiServerProcessors():
            sproc.send_notification("router-remove", data)

    def on_cascade_upstream_router_wan_connection_change(self, api_client, data):
        ret = False
        for router_id, item in data.items():
            tlist = _Helper.protocolWanConnectionToPrefixList(item["wan-connection"])
            ret |= self.param.prefix_pool.setExcludePrefixList("upstream-wan-%s" % (router_id), tlist)
        if ret:
            os.kill(os.getpid(), signal.SIGHUP)
            raise Exception("prefix duplicates with upstream router %s, autofix it and restart" % (router_id))

        # notify downstream
        for sproc in self._getApiServerProcessors():
            sproc.send_notification("wan-connection-change", data)

    def on_cascade_upstream_router_lan_prefix_list_change(self, api_client, data):
        # process by myself
        ret = False
        for router_id, item in data.items():
            tlist = _Helper.protocolPrefixListToPrefixList(item["lan-prefix-list"])
            ret |= self.param.prefix_pool.setExcludePrefixList("upstream-lan-%s" % (router_id), tlist)
        if ret:
            os.kill(os.getpid(), signal.SIGHUP)
            raise Exception("prefix duplicates with upstream router %s, autofix it and restart" % (router_id))
        self._upstreamLanPrefixListChange(api_client, data)

        # notify downstream
        for sproc in self._getApiServerProcessors():
            sproc.send_notification("lan-prefix-list-change", data)

    def on_cascade_upstream_router_client_add(self, api_client, data):
        # process by myself
        self._upstreamVpnHostRefresh(api_client)

        # notify downstream
        for sproc in self._getApiServerProcessors():
            sproc.send_notification("router-client-add", data)

    def on_cascade_upstream_router_client_change(self, api_client, data):
        # process by myself
        self._upstreamVpnHostRefresh(api_client)

        # notify downstream
        for sproc in self._getApiServerProcessors():
            sproc.send_notification("router-client-change", data)

    def on_cascade_upstream_router_client_remove(self, api_client, data):
        # process by myself
        self._upstreamVpnHostRefresh(api_client)

        # notify downstream
        for sproc in self._getApiServerProcessors():
            sproc.send_notification("router-client-remove", data)

    def on_cascade_downstream_up(self, sproc, data):
        self.routesDict[sproc.peer_ip] = dict()
        if len(data["router-list"]) > 0:
            self.on_cascade_downstream_router_add(sproc, data["router-list"])

    def on_cascade_downstream_down(self, sproc):
        self.on_cascade_downstream_router_remove(sproc, list(sproc.router_info.keys()))
        del self.routesDict[sproc.peer_ip]

    def on_cascade_downstream_router_add(self, sproc, data):
        # process by myself
        self._downstreamWanPrefixListCheck(data)
        for router_id, router_info in data.items():
            if "lan-prefix-list" in data[router_id]:
                self._updateRoutes(sproc.peer_ip, router_id, data[router_id]["lan-prefix-list"])
            if "client-list" in router_info:
                self.addSource("downstream-" + router_id)
                if len(router_info["client-list"]) > 0:
                    self._bridgeAddHost("downstream-" + router_id, router_info["client-list"])

        # notify upstream and other downstream
        if self._apiClientRegistered():
            self.apiClient.send_notification("router-add", data)
        for obj in self._getApiServerProcessorsExcept(sproc):
            obj.send_notification("router-add", data)

    def on_cascade_downstream_router_remove(self, sproc, data):
        # process by myself
        for router_id in data:
            self._bridgeRemoveSource("downstream-" + router_id)
            self._removeRoutes(sproc.peer_ip, router_id)
            self.param.prefix_pool.removeExcludePrefixList("downstream-wan-%s" % (router_id))

        # notify upstream and other downstream
        if self._apiClientRegistered():
            self.apiClient.send_notification("router-remove", data)
        for obj in self._getApiServerProcessorsExcept(sproc):
            obj.send_notification("router-remove", data)

    def on_cascade_downstream_router_wan_connection_change(self, sproc, data):
        # process by myself
        self._downstreamWanPrefixListCheck(data)

        # notify upstream and other downstream
        if self._apiClientRegistered():
            self.apiClient.send_notification("router-wan-connection-change", data)
        for obj in self._getApiServerProcessorsExcept(sproc):
            obj.send_notification("router-wan-connection-change", data)

    def on_cascade_downstream_router_lan_prefix_list_change(self, sproc, data):
        # process by myself
        for router_id in data:
            self._updateRoutes(sproc.peer_ip, router_id, data[router_id]["lan-prefix-list"])

        # notify upstream and other downstream
        if self._apiClientRegistered():
            self.apiClient.send_notification("router-lan-prefix-list-change", data)
        for obj in self._getApiServerProcessorsExcept(sproc):
            obj.send_notification("router-lan-prefix-list-change", data)

    def on_cascade_downstream_router_client_add(self, sproc, data):
        # process by myself
        for router_id, router_info in data.items():
            self._bridgeAddHost("downstream-" + router_id, router_info["client-list"])

        # notify upstream and other downstream
        if self._apiClientRegistered():
            self.apiClient.send_notification("router-client-add", data)
        for obj in self._getApiServerProcessorsExcept(sproc):
            obj.send_notification("router-client-add", data)

    def on_cascade_downstream_router_client_change(self, sproc, data):
        # process by myself
        for router_id, router_info in data.items():
            self._bridgeChangeHost("downstream-" + router_id, router_info["client-list"])

        # notify upstream and other downstream
        if self._apiClientRegistered():
            self.apiClient.send_notification("router-client-change", data)
        for obj in self._getApiServerProcessorsExcept(sproc):
            obj.send_notification("router-client-change", data)

    def on_cascade_downstream_router_client_remove(self, sproc, data):
        # process by myself
        for router_id, router_info in data.items():
            self._bridgeRemoveHost("downstream-" + router_id, router_info["client-list"])

        # notify upstream and other downstream
        if self._apiClientRegistered():
            self.apiClient.send_notification("router-client-remove", data)
        for obj in self._getApiServerProcessorsExcept(sproc):
            obj.send_notification("router-client-remove", data)

    def _clientAddOrChange(self, type, source_id, ip_data_dict):
        # process by myself
        self.router_info[self.param.uuid]["client-list"].update(ip_data_dict)

        # notify upstream & downstream
        data = {
            self.param.uuid: {
                "client-list": ip_data_dict,
            },
        }
        if self._apiClientConnected():
            self.apiClient.send_notification("router-client-%s" % (type), data)
        for sproc in self._getApiServerProcessors():
            sproc.send_notification("router-client-%s" % (type), data)

    def _wanConnectionChange(self):
        # process by myself
        if self.param.managers["wan"].wanConnPlugin.is_connected():
            self.router_info[self.param.uuid]["wan-connection"] = {
                "main": {
                    "ip": self.param.managers["wan"].wanConnPlugin.get_ip(),
                    "netmask": self.param.managers["wan"].wanConnPlugin.get_netmask(),
                    "is-ip-public": self.param.managers["wan"].wanConnIpIsPublic,
                    "extra-prefix-list": _Helper.prefixListToProtocolPrefixList(self.param.managers["wan"].wanConnPlugin.get_extra_prefix_list()),
                },
            }
        else:
            self.router_info[self.param.uuid]["wan-connection"] = dict()

        # notify upstream & downstream
        data = {
            self.param.uuid: {
                "wan-connection": self.router_info[self.param.uuid]["wan-connection"],
            },
        }
        if self._apiClientConnected():
            self.apiClient.send_notification("router-wan-connection-change", data)
        for sproc in self._getApiServerProcessors():
            sproc.send_notification("router-wan-connection-change", data)

    def _upstreamLanPrefixListChange(self, api_client, data):
        for router_id in data:
            if "lan-prefix-list" not in data[router_id]:
                continue                # called by on_cascade_upstream_router_add()
            if router_id == api_client.peer_uuid:
                tlist = list(data[router_id]["lan-prefix-list"])
                prefix = util.ipMaskToPrefix(self.vpnPlugin.get_local_ip(), self.vpnPlugin.get_netmask())
                tlist.remove(prefix[0] + "/" + prefix[1])
            else:
                tlist = data[router_id]["lan-prefix-list"]
            self._updateRoutes(api_client.peer_ip, router_id, tlist)

    def _bridgeAddSource(self, source_id):
        for bridge in [self.param.managers["lan"].defaultBridge] + [x.get_bridge() for x in self.param.managers["lan"].vpnsPluginList]:
            bridge.on_source_add(source_id)

    def _bridgeRemoveSource(self, source_id):
        for bridge in [self.param.managers["lan"].defaultBridge] + [x.get_bridge() for x in self.param.managers["lan"].vpnsPluginList]:
            bridge.on_source_remove(source_id)

    def _bridgeAddHost(self, source_id, ip_data_dict):
        for bridge in [self.param.managers["lan"].defaultBridge] + [x.get_bridge() for x in self.param.managers["lan"].vpnsPluginList]:
            bridge.on_host_add(source_id, ip_data_dict)

    def _bridgeChangeHost(self, source_id, ip_data_dict):
        for bridge in [self.param.managers["lan"].defaultBridge] + [x.get_bridge() for x in self.param.managers["lan"].vpnsPluginList]:
            bridge.on_host_change(source_id, ip_data_dict)

    def _bridgeRemoveHost(self, source_id, ip_list):
        for bridge in [self.param.managers["lan"].defaultBridge] + [x.get_bridge() for x in self.param.managers["lan"].vpnsPluginList]:
            bridge.on_host_remove(source_id, ip_list)

    def _bridgeRefreshHost(self, source_id, ip_list):
        for bridge in [self.param.managers["lan"].defaultBridge] + [x.get_bridge() for x in self.param.managers["lan"].vpnsPluginList]:
            bridge.on_host_refresh(source_id, ip_list)

    def _downstreamWanPrefixListCheck(self, data):
        # check downstream wan-prefix and restart if neccessary
        show_router_id = None
        for router_id, item in data.items():
            if "wan-connection" not in item:
                continue        # used when called by on_cascade_downstream_router_add()
            tlist = _Helper.protocolWanConnectionToPrefixList(item["wan-connection"])
            if self.param.prefix_pool.setExcludePrefixList("downstream-wan-%s" % (router_id), tlist):
                show_router_id = router_id
        if show_router_id is not None:
            os.kill(os.getpid(), signal.SIGHUP)
            raise Exception("prefix duplicates with downstream router %s, autofix it and restart" % (show_router_id))

    def _upstreamVpnHostRefresh(self, api_client):
        # we need to differentiate upstream router and other client, so we do refresh instead of add/change/remove
        ipDataDict = dict()

        # add upstream routers into ipDataDict
        upstreamRouterLocalIpList = []
        if self._apiClientRegistered():
            curUpstreamId = api_client.peer_uuid
            curUpstreamIp = api_client.peer_ip
            curUpstreamLocalIp = self.vpnPlugin.get_local_ip()
            while True:
                data = api_client.router_info[curUpstreamId]

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
        for router in api_client.router_info.values():
            if "client-list" in router:
                for ip, data in router["client-list"].items():
                    if ip in upstreamRouterLocalIpList:
                        continue
                    ipDataDict[ip] = data

        # refresh to all bridges
        self._bridgeRefreshHost("upstream-vpn", ipDataDict)

    def _apiClientRegistered(self):
        return self.apiClient is not None and self.apiClient.bRegistered

    def _apiClientConnected(self):
        return self.apiClient is not None and self.apiClient.bConnected

    def _getApiServerProcessors(self):
        ret = []
        if self.apiServer is None:
            return ret
        for obj in self.apiServer.sprocList:
            if obj.peer_uuid is not None:
                ret.append(obj)
        return ret

    def _getApiServerProcessorsExcept(self, sproc):
        ret = []
        if self.apiServer is None:
            return ret
        for obj in self.apiServer.sprocList:
            if obj.peer_uuid is not None and obj != sproc:
                ret.append(obj)
        return ret

    def _updateRoutes(self, gateway_ip, router_id, prefix_list):
        if router_id not in self.routesDict[gateway_ip]:
            self.routesDict[gateway_ip][router_id] = []
        with pyroute2.IPRoute() as ipp:
            # remove routes
            tlist = list(self.routesDict[gateway_ip][router_id])
            for prefix in tlist:
                if prefix not in prefix_list:
                    try:
                        ipp.route("del", dst=self.__prefixConvert(prefix))
                    except pyroute2.netlink.exceptions.NetlinkError as e:
                        if e[0] == 3 and e[1] == "No such process":
                            pass        # route does not exist, ignore this error
                        raise
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
                    try:
                        ipp.route("del", dst=self.__prefixConvert(prefix))
                    except pyroute2.netlink.exceptions.NetlinkError as e:
                        if e[0] == 3 and e[1] == "No such process":
                            pass        # route does not exist, ignore this error
                        raise
                del self.routesDict[gateway_ip][router_id]

    def __prefixConvert(self, prefix):
        tl = prefix.split("/")
        return tl[0] + "/" + str(util.ipMaskToLen(tl[1]))


class _ApiClient(msghole.EndPoint):

    # no exception is allowed in on_cascade_upstream_fail(),  on_cascade_upstream_error(),  on_cascade_upstream_down().
    # on_cascade_upstream_fail() would be called if there's error before client is registered.
    # on_cascade_upstream_error() would be called if there's error after client is registered.

    def __init__(self, pObj, remote_ip):
        super().__init__()
        self.pObj = pObj
        self.param = pObj.param
        self.logger = pObj.logger

        self.peer_ip = remote_ip
        sc = Gio.SocketClient.new()
        sc.set_family(Gio.SocketFamily.IPV4)
        sc.set_protocol(Gio.SocketProtocol.TCP)

        self.logger.info("Establishing CASCADE-API connection.")
        self.peer_uuid = None
        self.router_info = None
        self.bConnected = False
        self.bRegistered = False
        sc.connect_to_host_async(self.peer_ip, self.pObj.apiPort, None, self._on_connect)

    def _on_connect(self, source_object, res):
        try:
            conn = source_object.connect_to_host_finish(res)
            super().set_iostream_and_start(conn)

            # send register command
            data = dict()
            data["my-id"] = self.param.uuid
            data["router-list"] = dict()
            data["router-list"].update(self.pObj.router_info)
            for sproc in self.pObj._getApiServerProcessors():
                data["router-list"].update(sproc.router_info)
                data["router-list"][sproc.peer_uuid]["parent"] = self.param.uuid
            super().exec_command("register", data, self._on_register_return, self._on_register_error)

            self.bConnected = True
        except Exception as e:
            self.logger.error("Failed to establish CASCADE-API connection", exc_info=True)   # fixme
            self.param.manager_caller.call("on_cascade_upstream_fail", self, e)
            self.close()

    def _on_register_return(self, data):
        self.peer_uuid = data["my-id"]
        self.router_info = data["router-list"]
        self.bRegistered = True
        self.logger.info("CASCADE-API connection established.")
        _Helper.logRouterAdd(self.router_info, self.logger)
        self.param.manager_caller.call("on_cascade_upstream_up", self, data)

    def _on_register_error(self, reason):
        m = re.match("UUID (.*) duplicate", reason)
        if m is not None:
            for sproc in self.pObj._getApiServerProcessors():
                if m.group(1) in sproc.router_info:
                    self.pObj.banUuidList.append(m.group(1))
                    sproc.close()
        raise Exception(reason)

    def on_error(self, excp):
        if self.bRegistered:
            self.logger.error("CASCADE-API connection disconnected with error.", exc_info=True)  # fixme
            self.param.manager_caller.call("on_cascade_upstream_error", self, excp)
        else:
            self.logger.error("Failed to establish CASCADE-API connection.", exc_info=True)      # fixme
            self.param.manager_caller.call("on_cascade_upstream_fail", self, excp)

    def on_close(self):
        if self.bRegistered:
            self.param.manager_caller.call("on_cascade_upstream_down", self)
            _Helper.logRouterRemoveAll(self.router_info, self.logger)

    def on_notification_router_add(self, data):
        assert self.bRegistered

        ret = self._routerIdDuplicityCheck(data)
        if ret is not None:
            uuid, sproc = ret
            if sproc is not None:
                self.pObj.banUuidList.append(uuid)
                sproc.close()
            raise Exception("UUID %s duplicate" % (uuid))

        self.router_info.update(data)
        _Helper.logRouterAdd(data, self.logger)
        self.param.manager_caller.call("on_cascade_upstream_router_add", self, data)

    def on_notification_router_remove(self, data):
        assert self.bRegistered
        self.param.manager_caller.call("on_cascade_upstream_router_remove", self, data)
        _Helper.logRouterRemove(data, self.router_info, self.logger)
        for router_id in data:
            del self.router_info[router_id]

    def on_notification_router_cascade_vpn_change(self, data):
        assert self.bRegistered
        for router_id, item in data.items():
            self.router_info[router_id]["cascade-vpn"] = item["cascade-vpn"]
        self.param.manager_caller.call("on_cascade_upstream_router_cascade_vpn_change", self, data)

    def on_notification_router_wan_connection_change(self, data):
        assert self.bRegistered
        for router_id, item in data.items():
            self.router_info[router_id]["wan-connection"] = item["wan-connection"]
        self.param.manager_caller.call("on_cascade_upstream_router_wan_connection_change", self, data)

    def on_notification_router_lan_prefix_list_change(self, data):
        assert self.bRegistered
        for router_id, item in data.items():
            self.router_info[router_id]["lan-prefix-list"] = item["lan-prefix-list"]
        self.param.manager_caller.call("on_cascade_upstream_router_lan_prefix_list_change", self, data)

    def on_notification_router_client_add(self, data):
        assert self.bRegistered
        for router_id, item in data.items():
            self.router_info[router_id]["client-list"].update(item["client-list"])
        _Helper.logRouterClientAdd(data, self.logger)
        self.param.manager_caller.call("on_cascade_upstream_router_client_add", self, data)

    def on_notification_router_client_change(self, data):
        assert self.bRegistered
        for router_id, item in data.items():
            self.router_info[router_id]["client-list"].update(item["client-list"])
        # no log needed for client change
        self.param.manager_caller.call("on_cascade_upstream_router_client_change", self, data)

    def on_notification_router_client_remove(self, data):
        assert self.bRegistered
        self.param.manager_caller.call("on_cascade_upstream_router_client_remove", self, data)
        _Helper.logRouterClientRemove(data, self.router_info, self.logger)
        for router_id, item in data.items():
            for ip in item["client-list"]:
                del self.router_info[router_id]["client-list"][ip]

    def _routerIdDuplicityCheck(self, data):
        if self.param.uuid in data:
            return (self.param.uuid, None)
        for sproc in self.pObj._getApiServerProcessors():
            ret = set(sproc.router_info.keys()) & set(data.keys())
            ret = list(ret)
            if len(ret) > 0:
                return (ret[0], sproc)
        return None


class _ApiServer:

    def __init__(self, pObj):
        self.pObj = pObj
        self.param = pObj.param
        self.logger = pObj.logger

        self.serverListener = Gio.SocketListener.new()
        addr = Gio.InetSocketAddress.new_from_string("0.0.0.0", self.pObj.apiPort)
        self.serverListener.add_address(addr, Gio.SocketType.STREAM, Gio.SocketProtocol.TCP)
        self.serverListener.accept_async(None, self._on_accept)

        self.sprocList = []

    def close(self):
        for sproc in self.sprocList:
            sproc.close()
        self.serverListener.close()

    def _on_accept(self, source_object, res):
        conn, dummy = source_object.accept_finish(res)
        peer_ip = conn.get_remote_address().get_address().to_string()

        bFound = False
        for p in self.param.managers["lan"].vpnsPluginList:
            netobj = ipaddress.IPv4Network(p.get_bridge().get_prefix()[0] + "/" + p.get_bridge().get_prefix()[1])
            if ipaddress.IPv4Address(peer_ip) in netobj:
                bFound = True
                break
        if not bFound:
            self.logger.error("CASCADE-API client %s rejected, invalid client IP address." % (peer_ip))
            conn.close()
            return

        for sproc in self.sprocList:
            if sproc.peer_ip == peer_ip:
                self.logger.error("CASCADE-API client %s rejected, multiple channel per IP address." % (peer_ip))
                conn.close()
                return

        self.sprocList.append(_ApiServerProcessor(self.pObj, self, conn))
        self.serverListener.accept_async(None, self._on_accept)


class _ApiServerProcessor(msghole.EndPoint):

    def __init__(self, pObj, serverObj, conn):
        super().__init__()

        self.pObj = pObj
        self.param = pObj.param
        self.logger = pObj.logger

        self.serverObj = serverObj

        self.peer_ip = conn.get_remote_address().get_address().to_string()
        self.peer_uuid = None
        self.router_info = None

        self.registerTimer = GObject.timeout_add_seconds(180, self._registerTimerCallback)

        super().set_iostream_and_start(conn)

    def on_error(self, e):
        self.logger.error("Error occured in server processor for client \"%s\"" % (self.peer_ip), exc_info=True)

    def on_close(self):
        if self.peer_uuid is not None:
            self.param.manager_caller.call("on_cascade_downstream_down", self)
            _Helper.logRouterRemoveAll(self.router_info, self.logger)
        self.router_info = None
        self.peer_uuid = None
        self.logger.info("CASCADE-API client %s disconnected." % (self.peer_ip))
        self.serverObj.sprocList.remove(self)

    def on_command_register(self, data, return_callback, error_callback):
        try:
            # check
            uuid = self._routerIdDuplicityCheck(data["router-list"])
            if uuid is not None:
                self.logger.error("CASCADE-API client %s rejected, UUID %s duplicate." % (self.peer_ip, uuid))
                error_callback("UUID %s duplicate" % (uuid))
                self.close()
                return

            # process
            self.peer_uuid = data["my-id"]
            self.router_info = data["router-list"]
            self.logger.info("CASCADE-API client %s registered." % (self.peer_ip))
            _Helper.logRouterAdd(self.router_info, self.logger)
            self.param.manager_caller.call("on_cascade_downstream_up", self, data)

            # send reply
            data2 = dict()
            data2["my-id"] = self.param.uuid
            data2["router-list"] = dict()
            data2["router-list"].update(self.pObj.router_info)
            if self.pObj._apiClientRegistered():
                data2["router-list"][self.param.uuid]["parent"] = self.pObj.apiClient.peer_uuid
                data2["router-list"].update(self.pObj.apiClient.router_info)
            for sproc in self.pObj._getApiServerProcessorsExcept(self):
                data2["router-list"].update(sproc.router_info)
                data2["router-list"][sproc.peer_uuid]["parent"] = self.param.uuid
            return_callback(data2)
        except:
            error_callback("internal error")
            raise

    def on_notification_router_add(self, data):
        assert self.peer_uuid is not None

        uuid = self._routerIdDuplicityCheck(data)
        if uuid is not None:
            raise Exception("UUID %s duplicate" % (uuid))

        self.router_info.update(data)
        _Helper.logRouterAdd(data, self.logger)
        self.param.manager_caller.call("on_cascade_downstream_router_add", self, data)

    def on_notification_router_remove(self, data):
        assert self.peer_uuid is not None

        self.param.manager_caller.call("on_cascade_downstream_router_remove", self, data)
        _Helper.logRouterRemove(data, self.router_info, self.logger)
        for router_id in data:
            del self.router_info[router_id]

    def on_notification_router_wan_connection_change(self, data):
        assert self.peer_uuid is not None

        for router_id, item in data.items():
            self.router_info[router_id]["wan-connection"] = item["wan-connection"]
        self.param.manager_caller.call("on_cascade_downstream_router_wan_connection_change", self, data)

    def on_notification_router_lan_prefix_list_change(self, data):
        assert self.peer_uuid is not None

        for router_id, item in data.items():
            self.router_info[router_id]["lan-prefix-list"] = item["lan-prefix-list"]
        self.param.manager_caller.call("on_cascade_downstream_router_lan_prefix_list_change", self, data)

    def on_notification_router_client_add(self, data):
        assert self.peer_uuid is not None

        for router_id, item in data.items():
            self.router_info[router_id]["client-list"].update(item["client-list"])
        _Helper.logRouterClientAdd(data, self.logger)
        self.param.manager_caller.call("on_cascade_downstream_router_client_add", self, data)

    def on_notification_router_client_change(self, data):
        assert self.peer_uuid is not None

        for router_id, item in data.items():
            self.router_info[router_id]["client-list"].update(item["client-list"])
        # no log needed for client change
        self.param.manager_caller.call("on_cascade_downstream_router_client_change", self, data)

    def on_notification_router_client_remove(self, data):
        assert self.peer_uuid is not None

        self.param.manager_caller.call("on_cascade_downstream_router_client_remove", self, data)
        _Helper.logRouterClientRemove(data, self.router_info, self.logger)
        for router_id, item in data.items():
            for ip in item["client-list"]:
                del self.router_info[router_id]["client-list"][ip]

    def _routerIdDuplicityCheck(self, data):
        if self.param.uuid in data:
            return self.param.uuid
        if self.pObj._apiClientRegistered():
            ret = set(self.pObj.apiClient.router_info) & set(data.keys())
            ret = list(ret)
            if len(ret) > 0:
                return ret[0]
        for sproc in self.pObj._getApiServerProcessors():
            ret = set(sproc.router_info.keys()) & set(data.keys())
            ret = list(ret)
            if len(ret) > 0:
                return ret[0]
        return None

    def _registerTimerCallback(self):
        try:
            if self.peer_uuid is None:
                self.logger.error("CASCADE-API client %s rejected, no register from client." % (self.peer_ip))
                self.close()
        except:
            self.logger.error("Error occured in register timer callback for client \"%s\"" % (self.peer_ip), exc_info=True)
        finally:
            self.registerTimer = None
            return False


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
    def protocolWanConnectionToPrefixList(wanConn):
        ret = []
        for conn in wanConn.values():
            ret.append(util.ipMaskToPrefix(conn["ip"], conn["netmask"]))
            if "extra-prefix-list" in conn:
                for prefix in conn["extra-prefix-list"]:
                    tlist = prefix.split("/")
                    ret.append((tlist[0], tlist[1]))
        return ret

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
