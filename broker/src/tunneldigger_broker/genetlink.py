'''
Netlink message generation/parsing

Copyright 2007        Johannes Berg <johannes@sipsolutions.net>

GPLv2+; See copying for details.
'''

import struct
from .netlink import NLM_F_REQUEST, NLMSG_MIN_TYPE, Message, parse_attributes
from .netlink import NulStrAttr, Connection, NETLINK_GENERIC

CTRL_CMD_UNSPEC       = 0
CTRL_CMD_NEWFAMILY    = 1
CTRL_CMD_DELFAMILY    = 2
CTRL_CMD_GETFAMILY    = 3
CTRL_CMD_NEWOPS       = 4
CTRL_CMD_DELOPS       = 5
CTRL_CMD_GETOPS       = 6

CTRL_ATTR_UNSPEC      = 0
CTRL_ATTR_FAMILY_ID   = 1
CTRL_ATTR_FAMILY_NAME = 2
CTRL_ATTR_VERSION     = 3
CTRL_ATTR_HDRSIZE     = 4
CTRL_ATTR_MAXATTR     = 5
CTRL_ATTR_OPS         = 6

class GenlHdr:
    def __init__(self, cmd, version = 0):
        self.cmd = cmd
        self.version = version
    def _dump(self):
        return struct.pack("BBxx", self.cmd, self.version)

def _genl_hdr_parse(data):
    return GenlHdr(*struct.unpack("BBxx", data))

GENL_ID_CTRL        = NLMSG_MIN_TYPE

class GeNlMessage(Message):
    def __init__(self, family, cmd, attrs=[], flags=0, version=0):
        self.cmd = cmd
        self.attrs = attrs
        self.family = family
        Message.__init__(self, family, flags=flags,
                         payload=[GenlHdr(self.cmd, version = version)]+attrs)

    @staticmethod
    def recv(conn, multiple = False):
        msgs = conn.recv(multiple = multiple)
        genlmsgs = []
        if not multiple:
            msgs = [msgs]

        for msg in msgs:
            packet = msg.payload
            if not packet:
                continue

            hdr = _genl_hdr_parse(packet[:4])

            genlmsg = GeNlMessage(msg.type, hdr.cmd, [], msg.flags)
            genlmsg.attrs = parse_attributes(packet[4:])
            genlmsg.version = hdr.version
            genlmsgs.append(genlmsg)

        if not multiple:
            return genlmsgs[0]

        return genlmsgs

class Controller:
    def __init__(self, conn):
        self.conn = conn
    def get_family_id(self, family):
        a = NulStrAttr(CTRL_ATTR_FAMILY_NAME, family)
        m = GeNlMessage(GENL_ID_CTRL, CTRL_CMD_GETFAMILY,
                        flags=NLM_F_REQUEST, attrs=[a])
        m.send(self.conn)
        m = GeNlMessage.recv(self.conn)
        return m.attrs[CTRL_ATTR_FAMILY_ID].u16()

