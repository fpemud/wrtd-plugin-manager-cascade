#!/usr/bin/python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-

import os
import re
import json
import signal
import socket
import logging
import pyroute2
import msghole
from gi.repository import Gio
from . import util


def get_plugin_list():
    return ["cascade"]


def get_plugin(name):
    if name == "cascade":
        return _PluginObject()
    else:
        assert False


class _PluginObject:

    def init2(self, cfg, tmpDir, varDir, data):
        self.cascadeApiPort = 2221
        self.param = data
        self.logger = logging.getLogger(self.__module__ + "." + self.__class__.__name__)

        self.router_info = dict()

        self.vpnPlugin = None

        self.routesDict = dict()            # dict<gateway-ip, dict<router-id, list<prefix>>>

        self.apiClient = None

        self.apiServerList = []

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
        except:
            self.dispose()
            raise

    def dispose(self):
        for api_server in self.apiServerList:
            api_server.close()
        self.apiServerList = []

        if self.apiClient is not None:
            pass                # fixme

        if self.vpnPlugin is not None:
            self.vpnPlugin.stop()
            self.vpnPlugin = None
            self.logger.info("CASCADE-VPN deactivated.")

    def manager_initialized(self, name):
        if name == "apiserver":
            self.param.managers[name].register_endpoint_factory("cascade", ApiServerEndPointFactory(self))

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
            for api_server in self.apiServerList:
                ret["cascade"]["router-list"].update(api_server.router_info)
                ret["cascade"]["router-list"][api_server.peer_uuid]["parent"] = self.param.uuid

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
        for api_server in self.apiServerList:
            api_server.sproc.send_notification("router-cascade-vpn-change", data)

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
        for api_server in self.apiServerList:
            api_server.sproc.send_notification("router-cascade-vpn-change", data)

    def on_client_add(self, source_id, ip_data_dict):
        self._clientAddOrChange("add", source_id, ip_data_dict)

    def on_client_change(self, source_id, ip_data_dict):
        self._clientAddOrChange("change", source_id, ip_data_dict)

    def on_client_remove(self, source_id, ip_list):
        assert len(ip_list) > 0

        # process by myself
        for ip in ip_list:
            if ip in self.router_info[self.param.uuid]["client-list"]:
                del self.router_info[self.param.uuid]["client-list"][ip]
        for api_server in self.apiServerList:
            if api_server.peer_ip in ip_list:
                api_server.close()

        # notify upstream
        if self._apiClientConnected():
            data = dict()
            data[self.param.uuid] = dict()
            data[self.param.uuid]["client-list"] = ip_list
            self.apiClient.send_notification("router-client-remove", data)

        # notify downstream
        data = dict()
        data[self.param.uuid] = dict()
        data[self.param.uuid]["client-list"] = ip_list
        for api_server in self.apiServerList:
            api_server.sproc.send_notification("router-client-remove", data)

    def on_cascade_upstream_up(self, api_client, data):
        self.banUuidList = []
        self.routesDict[api_client.peer_ip] = dict()
        self.param.managers["lan"].add_source("upstream-vpn")
        self.on_cascade_upstream_router_add(api_client, data["router-list"])

    def on_cascade_upstream_fail(self, api_client, excp):
        self.vpnPlugin.disconnect()

    def on_cascade_upstream_down(self, api_client):
        if api_client.router_info is not None and len(api_client.router_info) > 0:
            self.on_cascade_upstream_router_remove(api_client, api_client.router_info.keys())
        self.param.managers["lan"].remove_source("upstream-vpn")
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
        for api_server in self.apiServerList:
            api_server.sproc.send_notification("router-add", data)

    def on_cascade_upstream_router_remove(self, api_client, data):
        assert len(data) > 0

        # process by myself
        self._upstreamVpnHostRefresh(api_client)
        for router_id in data:
            self.param.prefix_pool.removeExcludePrefixList("upstream-lan-%s" % (router_id))
            self.param.prefix_pool.removeExcludePrefixList("upstream-wan-%s" % (router_id))
            self._removeRoutes(api_client.peer_ip, router_id)

        # notify downstream
        for api_server in self.apiServerList:
            api_server.sproc.send_notification("router-remove", data)

    def on_cascade_upstream_router_wan_connection_change(self, api_client, data):
        ret = False
        for router_id, item in data.items():
            tlist = _Helper.protocolWanConnectionToPrefixList(item["wan-connection"])
            ret |= self.param.prefix_pool.setExcludePrefixList("upstream-wan-%s" % (router_id), tlist)
        if ret:
            os.kill(os.getpid(), signal.SIGHUP)
            raise Exception("prefix duplicates with upstream router %s, autofix it and restart" % (router_id))

        # notify downstream
        for api_server in self.apiServerList:
            api_server.sproc.send_notification("wan-connection-change", data)

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
        for api_server in self.apiServerList:
            api_server.sproc.send_notification("lan-prefix-list-change", data)

    def on_cascade_upstream_router_client_add(self, api_client, data):
        # process by myself
        self._upstreamVpnHostRefresh(api_client)

        # notify downstream
        for api_server in self.apiServerList:
            api_server.sproc.send_notification("router-client-add", data)

    def on_cascade_upstream_router_client_change(self, api_client, data):
        # process by myself
        self._upstreamVpnHostRefresh(api_client)

        # notify downstream
        for api_server in self.apiServerList:
            api_server.sproc.send_notification("router-client-change", data)

    def on_cascade_upstream_router_client_remove(self, api_client, data):
        # process by myself
        self._upstreamVpnHostRefresh(api_client)

        # notify downstream
        for api_server in self.apiServerList:
            api_server.sproc.send_notification("router-client-remove", data)

    def on_cascade_downstream_up(self, api_server, data):
        self.routesDict[api_server.peer_ip] = dict()
        if len(data["router-list"]) > 0:
            self.on_cascade_downstream_router_add(api_server, data["router-list"])

    def on_cascade_downstream_down(self, api_server):
        self.on_cascade_downstream_router_remove(api_server, list(api_server.router_info.keys()))
        del self.routesDict[api_server.peer_ip]

    def on_cascade_downstream_router_add(self, api_server, data):
        # process by myself
        self._downstreamWanPrefixListCheck(data)
        for router_id, router_info in data.items():
            if "lan-prefix-list" in data[router_id]:
                self._updateRoutes(api_server.peer_ip, router_id, data[router_id]["lan-prefix-list"])
            if "client-list" in router_info:
                self.param.managers["lan"].add_source("downstream-" + router_id)
                if len(router_info["client-list"]) > 0:
                    self.param.managers["lan"].add_client("downstream-" + router_id, router_info["client-list"])

        # notify upstream and other downstream
        if self._apiClientRegistered():
            self.apiClient.send_notification("router-add", data)
        for obj in self.apiServerList:
            if obj != api_server:
                obj.sproc.send_notification("router-add", data)

    def on_cascade_downstream_router_remove(self, api_server, data):
        # process by myself
        for router_id in data:
            self.param.managers["lan"].remove_source("downstream-" + router_id)
            self._removeRoutes(api_server.peer_ip, router_id)
            self.param.prefix_pool.removeExcludePrefixList("downstream-wan-%s" % (router_id))

        # notify upstream and other downstream
        if self._apiClientRegistered():
            self.apiClient.send_notification("router-remove", data)
        for obj in self.apiServerList:
            if obj != api_server:
                obj.sproc.send_notification("router-remove", data)

    def on_cascade_downstream_router_wan_connection_change(self, api_server, data):
        # process by myself
        self._downstreamWanPrefixListCheck(data)

        # notify upstream and other downstream
        if self._apiClientRegistered():
            self.apiClient.send_notification("router-wan-connection-change", data)
        for obj in self.apiServerList:
            if obj != api_server:
                obj.sproc.send_notification("router-wan-connection-change", data)

    def on_cascade_downstream_router_lan_prefix_list_change(self, api_server, data):
        # process by myself
        for router_id in data:
            self._updateRoutes(api_server.peer_ip, router_id, data[router_id]["lan-prefix-list"])

        # notify upstream and other downstream
        if self._apiClientRegistered():
            self.apiClient.send_notification("router-lan-prefix-list-change", data)
        for obj in self.apiServerList:
            if obj != api_server:
                obj.sproc.send_notification("router-lan-prefix-list-change", data)

    def on_cascade_downstream_router_client_add(self, api_server, data):
        # process by myself
        for router_id, router_info in data.items():
            self.param.managers["lan"].add_client("downstream-" + router_id, router_info["client-list"])

        # notify upstream and other downstream
        if self._apiClientRegistered():
            self.apiClient.send_notification("router-client-add", data)
        for obj in self.apiServerList:
            if obj != api_server:
                obj.sproc.send_notification("router-client-add", data)

    def on_cascade_downstream_router_client_change(self, api_server, data):
        # process by myself
        for router_id, router_info in data.items():
            self.param.managers["lan"].change_client("downstream-" + router_id, router_info["client-list"])

        # notify upstream and other downstream
        if self._apiClientRegistered():
            self.apiClient.send_notification("router-client-change", data)
        for obj in self.apiServerList:
            if obj != api_server:
                obj.sproc.send_notification("router-client-change", data)

    def on_cascade_downstream_router_client_remove(self, api_server, data):
        # process by myself
        for router_id, router_info in data.items():
            self.param.managers["lan"].remove_client("downstream-" + router_id, router_info["client-list"])

        # notify upstream and other downstream
        if self._apiClientRegistered():
            self.apiClient.send_notification("router-client-remove", data)
        for obj in self.apiServerList:
            if obj != api_server:
                obj.sproc.send_notification("router-client-remove", data)

    def _clientAddOrChange(self, type, source_id, ip_data_dict):
        assert len(ip_data_dict) > 0

        # process by myself
        self.router_info[self.param.uuid]["client-list"].update(ip_data_dict)

        # notify upstream
        if self._apiClientConnected():
            data = dict()
            data[self.param.uuid] = dict()
            data[self.param.uuid]["client-list"] = ip_data_dict
            self.apiClient.send_notification("router-client-%s" % (type), data)

        # notify downstream
        data = dict()
        data[self.param.uuid] = dict()
        data[self.param.uuid]["client-list"] = ip_data_dict
        for api_server in self.apiServerList:
            api_server.sproc.send_notification("router-client-%s" % (type), data)

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
        for api_server in self.apiServerList:
            api_server.sproc.send_notification("router-wan-connection-change", data)

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
        self.param.managers["lan"].refresh_client("upstream-vpn", ipDataDict)

    def _apiClientRegistered(self):
        return self.apiClient is not None and self.apiClient.bRegistered

    def _apiClientConnected(self):
        return self.apiClient is not None and self.apiClient.bConnected

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
        self.peer_ip = remote_ip

        sc = Gio.SocketClient.new()
        sc.set_family(Gio.SocketFamily.IPV4)
        sc.set_protocol(Gio.SocketProtocol.TCP)

        self.pObj.logger.info("Establishing CASCADE-API connection.")
        self.peer_uuid = None
        self.router_info = None
        self.bConnected = False
        self.bRegistered = False
        sc.connect_to_host_async(self.peer_ip, self.pObj.cascadeApiPort, None, self._on_connect)

    def _on_connect(self, source_object, res):
        try:
            conn = source_object.connect_to_host_finish(res)
            super().set_iostream_and_start(conn)

            # send register command
            data = dict()
            data["my-id"] = self.pObj.param.uuid
            data["router-list"] = dict()
            if True:
                data["router-list"].update(self.pObj.router_info)
                for api_server in self.pObj.apiServerList:
                    data["router-list"].update(api_server.router_info)
                    data["router-list"][api_server.peer_uuid]["parent"] = self.pObj.param.uuid
            super().exec_command("register", data, self._on_register_return, self._on_register_error)

            self.bConnected = True
        except Exception as e:
            self.pObj.logger.error("Failed to establish CASCADE-API connection", exc_info=True)   # fixme
            self.pObj.param.manager_caller.call("on_cascade_upstream_fail", self, e)
            self.close()

    def _on_register_return(self, data):
        self.peer_uuid = data["my-id"]
        self.router_info = data["router-list"]
        self.bRegistered = True
        self.pObj.logger.info("CASCADE-API connection established.")
        _Helper.logRouterAdd(self.router_info, self.pObj.logger)
        self.pObj.param.manager_caller.call("on_cascade_upstream_up", self, data)

    def _on_register_error(self, reason):
        m = re.match("UUID (.*) duplicate", reason)
        if m is not None:
            for api_server in self.pObj.apiServerList:
                if m.group(1) in api_server.router_info:
                    self.pObj.banUuidList.append(m.group(1))
                    api_server.close()
        raise Exception(reason)

    def on_error(self, excp):
        if not self.bRegistered:
            self.pObj.logger.error("Failed to establish CASCADE-API connection.", exc_info=True)      # fixme
            self.pObj.param.manager_caller.call("on_cascade_upstream_fail", self, excp)
        else:
            self.pObj.logger.error("CASCADE-API connection disconnected with error.", exc_info=True)  # fixme
            self.pObj.param.manager_caller.call("on_cascade_upstream_error", self, excp)

    def on_close(self):
        if not self.bRegistered:
            pass
        else:
            self.pObj.param.manager_caller.call("on_cascade_upstream_down", self)
            _Helper.logRouterRemoveAll(self.router_info, self.pObj.logger)

    def on_notification_router_add(self, data):
        assert self.bRegistered

        ret = self._routerIdDuplicityCheck(data)
        if ret is not None:
            uuid, api_server = ret
            if api_server is not None:
                self.pObj.banUuidList.append(uuid)
                api_server.close()
            raise Exception("UUID %s duplicate" % (uuid))

        self.router_info.update(data)
        _Helper.logRouterAdd(data, self.pObj.logger)
        self.pObj.param.manager_caller.call("on_cascade_upstream_router_add", self, data)

    def on_notification_router_remove(self, data):
        assert self.bRegistered
        self.pObj.param.manager_caller.call("on_cascade_upstream_router_remove", self, data)
        _Helper.logRouterRemove(data, self.router_info, self.pObj.logger)
        for router_id in data:
            del self.router_info[router_id]

    def on_notification_router_cascade_vpn_change(self, data):
        assert self.bRegistered
        for router_id, item in data.items():
            self.router_info[router_id]["cascade-vpn"] = item["cascade-vpn"]
        self.pObj.param.manager_caller.call("on_cascade_upstream_router_cascade_vpn_change", self, data)

    def on_notification_router_wan_connection_change(self, data):
        assert self.bRegistered
        for router_id, item in data.items():
            self.router_info[router_id]["wan-connection"] = item["wan-connection"]
        self.pObj.param.manager_caller.call("on_cascade_upstream_router_wan_connection_change", self, data)

    def on_notification_router_lan_prefix_list_change(self, data):
        assert self.bRegistered
        for router_id, item in data.items():
            self.router_info[router_id]["lan-prefix-list"] = item["lan-prefix-list"]
        self.pObj.param.manager_caller.call("on_cascade_upstream_router_lan_prefix_list_change", self, data)

    def on_notification_router_client_add(self, data):
        assert self.bRegistered
        for router_id, item in data.items():
            self.router_info[router_id]["client-list"].update(item["client-list"])
        _Helper.logRouterClientAdd(data, self.pObj.logger)
        self.pObj.param.manager_caller.call("on_cascade_upstream_router_client_add", self, data)

    def on_notification_router_client_change(self, data):
        assert self.bRegistered
        for router_id, item in data.items():
            self.router_info[router_id]["client-list"].update(item["client-list"])
        # no log needed for client change
        self.pObj.param.manager_caller.call("on_cascade_upstream_router_client_change", self, data)

    def on_notification_router_client_remove(self, data):
        assert self.bRegistered
        self.pObj.param.manager_caller.call("on_cascade_upstream_router_client_remove", self, data)
        _Helper.logRouterClientRemove(data, self.router_info, self.pObj.logger)
        for router_id, item in data.items():
            for ip in item["client-list"]:
                del self.router_info[router_id]["client-list"][ip]

    def _routerIdDuplicityCheck(self, data):
        if self.pObj.param.uuid in data:
            return (self.pObj.param.uuid, None)
        for api_server in self.pObj.apiServerList:
            ret = set(api_server.router_info.keys()) & set(data.keys())
            ret = list(ret)
            if len(ret) > 0:
                return (ret[0], api_server)
        return None


class ApiServerEndPointFactory:

    def __init__(self, pObj):
        self.pObj = pObj

    def new_endpoint(self, local_ip, local_port, peer_ip, peer_port, sproc):
        for api_server in self.pObj.apiServerList:
            if api_server.peer_ip == peer_ip:
                raise Exception("multiple channel per IP address")
        return ApiServerEndPoint(self.pObj, peer_ip, sproc)


class ApiServerEndPoint:

    def __init__(self, pObj, peer_ip, sproc):
        self.pObj = pObj
        self.peer_ip = peer_ip
        self.sproc = sproc
        self.peer_uuid = None
        self.router_info = None
        self.send_notification = sproc.send_notification
        self.close = sproc.close

    def init2(self, data):
        # check
        uuid = self._routerIdDuplicityCheck(data["router-list"])
        if uuid is not None:
            raise Exception("UUID %s duplicate" % (uuid))

        # process
        self.peer_uuid = data["my-id"]
        self.router_info = data["router-list"]
        self.pObj.logger.info("CASCADE client %s registered." % (self.peer_ip))
        _Helper.logRouterAdd(self.router_info, self.pObj.logger)
        self.pObj.apiServerList.append(self)
        self.pObj.param.manager_caller.call("on_cascade_downstream_up", self, data)

        # send reply
        data2 = dict()
        data2["my-id"] = self.pObj.param.uuid
        data2["router-list"] = dict()
        data2["router-list"].update(self.pObj.router_info)
        if self.pObj.hasValidApiClient():
            data2["router-list"][self.pObj.param.uuid]["parent"] = self.pObj.apiClient.peer_uuid
            data2["router-list"].update(self.pObj.apiClient.router_info)
        for api_server in self.pObj.apiServerList:
            if api_server != self:
                data2["router-list"].update(api_server.router_info)
                data2["router-list"][api_server.peer_uuid]["parent"] = self.pObj.param.uuid
        return data2

    def close2(self):
        self.pObj.param.manager_caller.call("on_cascade_downstream_down", self)
        try:
            self.pObj.apiServerList.remove(self)
        except ValueError:
            pass
        if self.router_info is not None:
            _Helper.logRouterRemoveAll(self.router_info, self.pObj.logger)

    def on_notification_router_add(self, data):
        uuid = self._routerIdDuplicityCheck(data)
        if uuid is not None:
            raise Exception("UUID %s duplicate" % (uuid))

        self.router_info.update(data)
        _Helper.logRouterAdd(data, self.pObj.logger)
        self.pObj.param.manager_caller.call("on_cascade_downstream_router_add", self, data)

    def on_notification_router_remove(self, data):
        self.pObj.param.manager_caller.call("on_cascade_downstream_router_remove", self, data)
        _Helper.logRouterRemove(data, self.router_info, self.pObj.logger)
        for router_id in data:
            del self.router_info[router_id]

    def on_notification_router_wan_connection_change(self, data):
        for router_id, item in data.items():
            self.router_info[router_id]["wan-connection"] = item["wan-connection"]
        self.pObj.param.manager_caller.call("on_cascade_downstream_router_wan_connection_change", self, data)

    def on_notification_router_lan_prefix_list_change(self, data):
        for router_id, item in data.items():
            self.router_info[router_id]["lan-prefix-list"] = item["lan-prefix-list"]
        self.pObj.param.manager_caller.call("on_cascade_downstream_router_lan_prefix_list_change", self, data)

    def on_notification_router_client_add(self, data):
        for router_id, item in data.items():
            self.router_info[router_id]["client-list"].update(item["client-list"])
        _Helper.logRouterClientAdd(data, self.pObj.logger)
        self.pObj.param.manager_caller.call("on_cascade_downstream_router_client_add", self, data)

    def on_notification_router_client_change(self, data):
        for router_id, item in data.items():
            self.router_info[router_id]["client-list"].update(item["client-list"])
        # no log needed for client change
        self.pObj.param.manager_caller.call("on_cascade_downstream_router_client_change", self, data)

    def on_notification_router_client_remove(self, data):
        self.pObj.param.manager_caller.call("on_cascade_downstream_router_client_remove", self, data)
        _Helper.logRouterClientRemove(data, self.router_info, self.pObj.logger)
        for router_id, item in data.items():
            for ip in item["client-list"]:
                del self.router_info[router_id]["client-list"][ip]

    def _routerIdDuplicityCheck(self, data):
        if self.pObj.param.uuid in data:
            return self.pObj.param.uuid
        if self.pObj.hasValidApiClient():
            ret = set(self.pObj.apiClient.router_info) & set(data.keys())
            ret = list(ret)
            if len(ret) > 0:
                return ret[0]
        for api_server in self.pObj.apiServerList:
            ret = set(api_server.router_info.keys()) & set(data.keys())
            ret = list(ret)
            if len(ret) > 0:
                return ret[0]
        return None


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
