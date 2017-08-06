#!/usr/bin/python3
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: t -*-

import ipaddress


def ipMaskToPrefix(ip, netmask):
    netobj = ipaddress.IPv4Network(ip + "/" + netmask, strict=False)
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
