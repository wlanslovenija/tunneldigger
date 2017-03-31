import socket

from ._ffi._conntrack import ffi, lib

__all__ = [
    'ConntrackError',
    'ConnectionManager',
]


class ConntrackError(Exception):
    """
    Base class for all exceptions produced by the connection manager.
    """

    pass


class ConnectionManager(object):
    """
    Interface to connection tracking API.
    """

    def __init__(self, family=socket.AF_INET):
        """
        Construct connection manager.
        """

        self.family = family

    def kill(self, proto, src, dst, sport, dport):
        """
        Remove a specific connection tracking entry.
        """

        return self.killall(proto, src, dst, sport, dport)

    def killall(self, proto=None, src=None, dst=None, sport=None, dport=None):
        """
        Remove all connection tracking entries matching the filter.
        """

        ct = lib.nfct_new()
        if not ct:
            raise ConntrackError("nfct_new failed")

        try:
            lib.nfct_set_attr_u8(ct, lib.ATTR_L3PROTO, self.family)
            if self.family == socket.AF_INET:
                # IPv4.
                if src:
                    lib.nfct_set_attr_u32(ct, lib.ATTR_IPV4_SRC, socket.inet_pton(self.family, src))
                if dst:
                    lib.nfct_set_attr_u32(ct, lib.ATTR_IPV4_DST, socket.inet_pton(self.family, dst))
            elif self.family == socket.AF_INET6:
                # IPv6.
                if src:
                    lib.nfct_set_attr_u32(ct, lib.ATTR_IPV6_SRC, socket.inet_pton(self.family, src))
                if dst:
                    lib.nfct_set_attr_u32(ct, lib.ATTR_IPV6_DST, socket.inet_pton(self.family, dst))
            else:
                raise ConntrackError("Unsupported address family: {}".format(self.family))

            if proto:
                # Layer 4 protocol.
                lib.nfct_set_attr_u8(ct, lib.ATTR_L4PROTO, proto)
            if sport:
                # Source port.
                lib.nfct_set_attr_u16(ct, lib.ATTR_PORT_SRC, socket.htons(sport))
            if dport:
                # Destination port.
                lib.nfct_set_attr_u16(ct, lib.ATTR_PORT_DST, socket.htons(dport))

            handle_query = lib.nfct_open(lib.CONNTRACK, 0)
            if not handle_query:
                raise ConntrackError("nfct_open failed")

            try:
                handle_update = lib.nfct_open(lib.CONNTRACK, 0)
                if not handle_update:
                    raise ConntrackError("nfct_open failed")

                def callback(entry_type, entry_ct):
                    if not lib.nfct_cmp(ct, entry_ct, lib.NFCT_CMP_ALL | lib.NFCT_CMP_MASK):
                        return lib.NFCT_CB_CONTINUE

                    # Remove any matching conntrack entries using the update handle.
                    lib.nfct_query(handle_update, lib.NFCT_Q_DESTROY, entry_ct)
                    return lib.NFCT_CB_CONTINUE

                try:
                    cb_handle = ffi.new_handle(callback)
                    lib.nfct_callback_register(handle_query, lib.NFCT_T_ALL, lib.query_callback, cb_handle)
                    family_ref = ffi.new('int*')
                    family_ref[0] = self.family
                    result = lib.nfct_query(handle_query, lib.NFCT_Q_DUMP, family_ref)
                    if result == -1:
                        raise ConntrackError("nfct_query failed")
                finally:
                    lib.nfct_close(handle_update)
            finally:
                lib.nfct_close(handle_query)
        finally:
            lib.nfct_destroy(ct)


@ffi.def_extern()
def query_callback(entry_type, entry_ct, data):
    """
    Callback dispatcher interface.
    """

    callback = ffi.from_handle(data)
    return callback(entry_type, entry_ct)
