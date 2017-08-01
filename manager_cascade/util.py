#!/usr/bin/python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-

import json
import ipaddress
from gi.repository import Gio


def ipMaskToPrefix(ip, netmask):
    netobj = ipaddress.IPv4Network(ip + "/" + netmask)
    return (str(netobj.network_address), str(netobj.netmask))


def bridgeGetIp(bridge):
    return str(ipaddress.IPv4Address(bridge.get_prefix()[0]) + 1)


def ipMaskToLen(mask):
    """255.255.255.0 -> 24"""

    netmask = 0
    netmasks = mask.split('.')
    for i in range(0, len(netmasks)):
        netmask *= 256
        netmask += int(netmasks[i])
    return 32 - (netmask ^ 0xFFFFFFFF).bit_length()


def prefixListConflict(prefixList1, prefixList2):
    for prefix1 in prefixList1:
        for prefix2 in prefixList2:
            netobj1 = ipaddress.IPv4Network(prefix1[0] + "/" + prefix1[1])
            netobj2 = ipaddress.IPv4Network(prefix2[0] + "/" + prefix2[1])
            if netobj1.overlaps(netobj2):
                return True
    return False


class JsonApiEndPoint:
    # sub-class must implement the following functions:
    #   on_command_XXX_return(self, data)
    #   on_command_XXX_error(self, reason)
    #   on_notification_XXX(self, data)
    #   on_error(self, excp)
    #   on_close(self)
    #
    # exception in on_command_XXX_return(), on_command_XXX_error(), on_notification_XXX() would close the object and iostream
    # no exception is allowed in on_error(), on_close().
    # close(), send_notification(), exec_command() should not be called in on_XXX().
    # This class is not thread-safe.

    def __init__(self):
        self.iostream = None
        self.dis = None
        self.dos = None
        self.command_received = None
        self.command_sent = None

    def set_iostream_and_start(self, iostream):
        assert self.iostream is None

        try:
            self.iostream = iostream
            self.dis = Gio.DataInputStream.new(iostream.get_input_stream())
            self.dos = Gio.DataOutputStream.new(iostream.get_output_stream())
            self.dis.read_line_async(0, None, self._on_receive)     # fixme: 0 should be PRIORITY_DEFAULT, but I can't find it
        except BaseException:
            self.dis = None
            self.dos = None
            self.iostream = None

    def close(self):
        if self.iostream is not None:
            self.on_close()
            self.iostream.close()
        self.command_sent = None
        self.command_received = None
        self.dis = None
        self.dos = None
        self.iostream = None

    def send_notification(self, notification, data):
        jsonObj = dict()
        jsonObj["notification"] = notification
        if data is not None:
            jsonObj["data"] = data
        self.dos.put_string(json.dumps(jsonObj) + "\n")

    def exec_command(self, command, data, return_callback=None, error_callback=None):
        assert self.command_sent is None

        jsonObj = dict()
        jsonObj["command"] = command
        if data is not None:
            jsonObj["data"] = data
        self.dos.put_string(json.dumps(jsonObj) + "\n")
        self.command_sent = (command, return_callback, error_callback)

    def _on_receive(self, source_object, res):
        try:
            line, len = source_object.read_line_finish_utf8(res)
            if line is None:
                raise Exception("socket closed by peer")

            jsonObj = json.loads(line)
            while True:
                if "command" in jsonObj:
                    if self.command_received is not None:
                        raise Exception("unexpected \"command\" message")
                    funcname = "on_command_" + jsonObj["command"].replace("-", "_")
                    if not hasattr(self, funcname):
                        raise Exception("no callback for command " + jsonObj["command"])
                    self.command_received = jsonObj["command"]
                    getattr(self, funcname)(jsonObj.get("data", None), self._send_return, self._send_error)
                    break

                if "notification" in jsonObj:
                    funcname = "on_notification_" + jsonObj["notification"].replace("-", "_")
                    if not hasattr(self, funcname):
                        raise Exception("no callback for notification " + jsonObj["notification"])
                    getattr(self, funcname)(jsonObj.get("data", None))
                    break

                if "return" in jsonObj:
                    if self.command_sent is None:
                        raise Exception("unexpected \"return\" message")
                    cmd, return_cb, error_cb = self.command_sent
                    if jsonObj["return"] is not None and return_cb is None:
                        raise Exception("no return callback specified for command " + cmd)
                    if return_cb is not None:
                        return_cb(jsonObj["return"])
                    self.command_sent = None
                    break

                if "error" in jsonObj:
                    if self.command_sent is None:
                        raise Exception("unexpected \"error\" message")
                    cmd, return_cb, error_cb = self.command_sent
                    if error_cb is None:
                        raise Exception("no error callback specified for command " + cmd)
                    error_cb(jsonObj["error"])
                    self.command_sent = None
                    break

                raise Exception("invalid message")

            self.dis.read_line_async(0, None, self._on_receive)
        except Exception as e:
            self.on_error(e)
            self.close()

    def _send_return(self, data):
        assert self.command_received is not None

        jsonObj = dict()
        jsonObj["return"] = data
        self.dos.put_string(json.dumps(jsonObj) + "\n")
        self.command_received = None

    def _send_error(self, data):
        assert self.command_received is not None

        jsonObj = dict()
        jsonObj["error"] = data
        self.dos.put_string(json.dumps(jsonObj) + "\n")
        self.command_received = None
