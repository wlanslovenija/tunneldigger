import conntrack
import netfilter.table
import netfilter.rule
import logging
import time
import traceback

from . import l2tp, protocol, network, tunnel as td_tunnel

# Logger.
logger = logging.getLogger("tunneldigger.broker")


class TunnelManager(object):
    """
    Tunnel manager.
    """

    def __init__(self, hook_manager, max_tunnels, tunnel_id_base, tunnel_port_base, namespace):
        """
        Constructs a tunnel manager.

        :param hook_manager: Hook manager
        :param max_tunnels: Maximum number of tunnels to allow
        :param tunnel_id_base: Base local tunnel identifier
        :param tunnel_port_base: Base local tunnel port
        :param namespace: Netfilter namespace to use
        """

        self.hook_manager = hook_manager
        self.max_tunnels = max_tunnels
        self.tunnel_id_base = tunnel_id_base
        self.tunnel_ids = set(xrange(tunnel_id_base, tunnel_id_base + max_tunnels + 1))
        self.tunnel_port_base = tunnel_port_base
        self.namespace = namespace
        self.tunnels = {}
        self.last_tunnel_created = None

    def create_tunnel(self, broker, address, uuid, remote_tunnel_id):
        """
        Creates a new tunnel.

        :param broker: Broker that received the tunnel request
        :param address: Remote tunnel endpoint address (host, port) tuple
        :param uuid: Unique tunnel identifier received from the remote host
        :param remote_tunnel_id: Remotely assigned tunnel identifier
        :return: True if a tunnel has been created, False otherwise
        """

        now = time.time()

        # Rate limit creation of new tunnels to at most one every 10 seconds to prevent the
        # broker from being overwhelmed with creating tunnels, especially on embedded devices.
        if self.last_tunnel_created is not None and now - self.last_tunnel_created < 10:
            return False

        try:
            tunnel_id = self.tunnel_ids.pop()
        except KeyError:
            return False

        logger.info("Creating tunnel %s:%s (%s) with id %d." % (address[0], address[1], uuid, tunnel_id))

        try:
            tunnel = td_tunnel.Tunnel(
                broker,
                (broker.address[0], self.tunnel_port_base + tunnel_id),
                address,
                uuid,
                tunnel_id,
                remote_tunnel_id
            )
            tunnel.register(broker.event_loop)
            tunnel.setup_tunnel()
            self.tunnels[tunnel_id] = tunnel
            self.last_tunnel_created = now
        except KeyboardInterrupt:
            raise
        except l2tp.L2TPTunnelExists:
            # Do not return the tunnel identifier into the pool.
            logger.warning("Tunnel identifier %d already exists." % tunnel_id)
            return False
        except:
            # Return tunnel identifier into the pool.
            self.tunnel_ids.add(tunnel_id)
            logger.error("Unhandled exception while creating tunnel %d:" % tunnel_id)
            logger.error(traceback.format_exc())
            return False

        return True

    def destroy_tunnel(self, tunnel):
        """
        Removes the given managed tunnel.

        :param tunnel: Previously created tunnel instance to remove
        """

        # Return the tunnel identifier to the broker.
        self.tunnel_ids.add(tunnel.tunnel_id)
        del self.tunnels[tunnel.tunnel_id]

    def initialize(self):
        """
        Sets up netfilter rules so new packets to the same port are redirected
        into the per-tunnel socket.
        """

        prerouting_chain = "L2TP_PREROUTING_%s" % self.namespace
        postrouting_chain = "L2TP_POSTROUTING_%s" % self.namespace
        nat = netfilter.table.Table('nat')
        self.rule_prerouting_jmp = netfilter.rule.Rule(jump=prerouting_chain)
        self.rule_postrouting_jmp = netfilter.rule.Rule(jump=postrouting_chain)

        try:
            nat.flush_chain(prerouting_chain)
            nat.delete_chain(prerouting_chain)
        except netfilter.table.IptablesError:
            pass

        try:
            nat.flush_chain(postrouting_chain)
            nat.delete_chain(postrouting_chain)
        except netfilter.table.IptablesError:
            pass

        nat.create_chain(prerouting_chain)
        nat.create_chain(postrouting_chain)
        try:
            nat.delete_rule('PREROUTING', self.rule_prerouting_jmp)
        except netfilter.table.IptablesError:
            pass
        nat.prepend_rule('PREROUTING', self.rule_prerouting_jmp)

        try:
            nat.delete_rule('POSTROUTING', self.rule_postrouting_jmp)
        except netfilter.table.IptablesError:
            pass
        nat.prepend_rule('POSTROUTING', self.rule_postrouting_jmp)

        # Initialize connection tracking manager.
        self.conntrack = conntrack.ConnectionManager()
        # Initialize netlink.
        self.netlink = l2tp.NetlinkInterface()

        # Initialize tunnels.
        for tunnel_id, session_id in self.netlink.session_list():
            if tunnel_id in self.tunnel_ids:
                logger.warning("Removing existing tunnel %d session %d." % (tunnel_id, session_id))
                self.netlink.session_delete(tunnel_id, session_id)

        for tunnel_id in self.netlink.tunnel_list():
            if tunnel_id in self.tunnel_ids:
                logger.warning("Removing existing tunnel %d." % tunnel_id)
                self.netlink.tunnel_delete(tunnel_id)

    def close(self):
        """
        Shuts down all managed tunnels and restores netfilter state. The tunnel
        manager instance should not be used after calling this method.
        """

        for tunnel in self.tunnels.values():
            try:
                tunnel.close()
            except:
                traceback.print_exc()

        # Restore netfilter rules.
        nat = netfilter.table.Table('nat')
        nat.delete_rule('PREROUTING', self.rule_prerouting_jmp)
        nat.delete_rule('POSTROUTING', self.rule_postrouting_jmp)
        nat.flush_chain('L2TP_PREROUTING_%s' % self.namespace)
        nat.flush_chain('L2TP_POSTROUTING_%s' % self.namespace)
        nat.delete_chain('L2TP_PREROUTING_%s' % self.namespace)
        nat.delete_chain('L2TP_POSTROUTING_%s' % self.namespace)

        del self.conntrack
        del self.netlink


class Broker(protocol.HandshakeProtocolMixin, network.Pollable):
    """
    Tunnel broker.
    """

    def __init__(self, address, interface, tunnel_manager):
        """
        Constructs a new tunnel broker.

        :param address: Address (host, port) tuple to bind to
        :param interface: Interface name to bind to
        :param tunnel_manager: Tunnel manager instance to use
        """

        super(Broker, self).__init__(address, interface)

        self.tunnel_manager = tunnel_manager
        self.hook_manager = tunnel_manager.hook_manager
        self.conntrack = tunnel_manager.conntrack
        self.netlink = tunnel_manager.netlink

        # Clear out the connection tracking tables.
        self.conntrack.killall(proto=conntrack.IPPROTO_UDP, src=self.address[0])
        self.conntrack.killall(proto=conntrack.IPPROTO_UDP, dst=self.address[0])

    def get_tunnel_manager(self):
        """
        Returns the tunnel manager for this broker.
        """

        return self.tunnel_manager

    def create_tunnel(self, address, uuid, remote_tunnel_id):
        """
        Called when a new tunnel should be created.

        :param address: Remote tunnel endpoint address (host, port) tuple
        :param uuid: Unique tunnel identifier received from the remote host
        :param remote_tunnel_id: Remotely assigned tunnel identifier
        :return: True if a tunnel has been created, False otherwise
        """

        return self.tunnel_manager.create_tunnel(self, address, uuid, remote_tunnel_id)
