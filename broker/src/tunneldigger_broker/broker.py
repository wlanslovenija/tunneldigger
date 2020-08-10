import logging
import socket
import time
import traceback
from collections import deque

from . import l2tp, protocol, network, tunnel as td_tunnel

# Logger.
logger = logging.getLogger("tunneldigger.broker")


class TunnelManager(object):
    """
    Tunnel manager.
    """

    def __init__(
        self,
        hook_manager,
        max_tunnels,
        tunnel_id_base,
        connection_rate_limit,
        connection_rate_limit_per_ip_count,
        connection_rate_limit_per_ip_time,
        pmtu_fixed,
        log_ip_addresses,
    ):
        """
        Constructs a tunnel manager.

        :param hook_manager: Hook manager
        :param max_tunnels: Maximum number of tunnels to allow
        :param tunnel_id_base: Base local tunnel identifier
        """

        self.hook_manager = hook_manager
        self.max_tunnels = max_tunnels
        self.tunnel_id_base = tunnel_id_base
        self.tunnel_ids = set(range(tunnel_id_base, tunnel_id_base + max_tunnels))
        self.tunnels = {}
        self.last_tunnel_created = None
        self.last_tunnel_created_per_ip = {} # Key: IP address Value: deque collection with timestamps
        self.connection_rate_limit = connection_rate_limit
        self.connection_rate_limit_per_ip_count = connection_rate_limit_per_ip_count
        self.connection_rate_limit_per_ip_time = connection_rate_limit_per_ip_time
        self.pmtu_fixed = pmtu_fixed
        self.require_unique_session_id = False
        self.log_ip_addresses = log_ip_addresses

    def report_usage(self, client_features):
        """
        Returns a number between 0 and 1 << 16 (i.e., a 16-bit number) indicating the load of the
        broker.

        :param client_features: Client feature flags
        """
        max_usage = 0xFFFF

        # If we require a unique session ID: report full usage for clients not supporting unique
        # session IDs.
        if self.require_unique_session_id and not (client_features & protocol.FEATURE_UNIQUE_SESSION_ID):
            return max_usage

        return int((float(len(self.tunnels)) / self.max_tunnels) * max_usage)

    def create_tunnel(self, broker, address, uuid, remote_tunnel_id, client_features):
        """
        Creates a new tunnel.

        :param broker: Broker that received the tunnel request
        :param address: Remote tunnel endpoint address (host, port) tuple
        :param uuid: Unique tunnel identifier received from the remote host
        :param remote_tunnel_id: Remotely assigned tunnel identifier
        :param client_features: Client feature flags
        :return: True if a tunnel has been created, False otherwise
        """

        now = time.time()

        if self.log_ip_addresses:
            tunnel_str = "%s:%s (%s)" % (address[0], address[1], uuid)
        else:
            tunnel_str = "(%s)" % uuid

        # Rate limit creation of new tunnels to at most one every 10 seconds to prevent the
        # broker from being overwhelmed with creating tunnels, especially on embedded devices.
        # We do this before the per-IP rate limiting so that these failed attempts do not count towards the latter.
        if self.last_tunnel_created is not None and now - self.last_tunnel_created < self.connection_rate_limit:
            logger.info("Rejecting tunnel %s due to global rate limiting: last tunnel was created too recently" % tunnel_str)
            return False

        # Rate limit creation of new tunnels with the same IP address.
        # Runs broker.connection-rate-limit hook if threshold exceeded:
        if self.connection_rate_limit_per_ip_count > 0 and self.connection_rate_limit_per_ip_time > 0:
            if address[0] not in self.last_tunnel_created_per_ip:
                # Create deque with max size if IP address does not exist in dict
                self.last_tunnel_created_per_ip[address[0]] = deque([], self.connection_rate_limit_per_ip_count)
            tunnelCollection = self.last_tunnel_created_per_ip[address[0]]
            if len(tunnelCollection) >= self.connection_rate_limit_per_ip_count:
                # We have "count" many connection attempts registered from this IP.
                # Check if they are all within "time".
                delta = now - tunnelCollection[0] # Delta of oldest timestamp in collection and now
                if delta <= self.connection_rate_limit_per_ip_time:
                    logger.info(
                        "Rejecting tunnel %s due to per-IP rate limiting: %d attempts in %d seconds",
                        tunnel_str,
                        len(tunnelCollection),
                        int(delta),
                    )
                    broker.hook_manager.run_hook(
                        'broker.connection-rate-limit',
                        address[0],
                        address[1],
                        uuid,
                    )
                    # Keep the data in the queue. The client may connect again once TIME seconds
                    # passed since the oldest registered connection attempt.
                    # (This rejected attempt does not count to that.)
                    return False
            # Append current timestamp at the end of deque collection so the oldest (first) will be dropped.
            tunnelCollection.append(now)

        try:
            tunnel_id = self.tunnel_ids.pop()
        except KeyError:
            logger.warning("No more tunnel IDs available -- %d active tunnels", self.tunnels)
            return False

        logger.info("Creating tunnel %s with id %d.", tunnel_str, tunnel_id)

        try:
            tunnel = td_tunnel.Tunnel(
                broker=broker,
                address=broker.address,
                endpoint=address,
                uuid=uuid,
                tunnel_id=tunnel_id,
                remote_tunnel_id=remote_tunnel_id,
                pmtu_fixed=self.pmtu_fixed,
                client_features=client_features,
            )
            tunnel.register(broker.event_loop)
            tunnel.setup_tunnel()
            self.tunnels[tunnel_id] = tunnel
            self.last_tunnel_created = now
        except KeyboardInterrupt:
            raise
        except l2tp.L2TPTunnelExists as e:
            # Do not return the tunnel identifier into the pool.
            logger.warning("Tunnel identifier %d already exists." % e.tunnel_id)
            return False
        except l2tp.L2TPSessionExists as e:
            # Return tunnel identifier into the pool.
            self.tunnel_ids.add(tunnel_id)
            logger.warning("Session identifier %d already exists." % e.session_id)
            # From now on, demand unique session IDs
            self.require_unique_session_id = True
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
        Shuts down all managed tunnels. The tunnel manager instance
        should not be used after calling this method.
        """

        for tunnel in list(self.tunnels.values()):
            try:
                tunnel.close()
            except:
                traceback.print_exc()

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
        self.netlink = tunnel_manager.netlink

    def get_tunnel_manager(self):
        """
        Returns the tunnel manager for this broker.
        """

        return self.tunnel_manager

    def create_tunnel(self, address, uuid, remote_tunnel_id, client_features):
        """
        Called when a new tunnel should be created.

        :param address: Remote tunnel endpoint address (host, port) tuple
        :param uuid: Unique tunnel identifier received from the remote host
        :param remote_tunnel_id: Remotely assigned tunnel identifier
        :param client_features: Client feature flags
        :return: True if a tunnel has been created, False otherwise
        """

        return self.tunnel_manager.create_tunnel(self, address, uuid, remote_tunnel_id, client_features)

    def message(self, address, msg_type, msg_data, raw_length):
        """
        Called when a new protocol message is received.

        :param address: Source address (host, port) tuple
        :param msg_type: Message type
        :param msg_data: Message payload
        :param raw_length: Length of the raw message (including headers)
        """

        # Due to SO_REUSEPORT bugs, we also see messags here that really ought to
        # go to an established tunnel.  So check the tunnels first.
        for tunnel in self.tunnel_manager.tunnels.values():
            if tunnel.address == self.address and tunnel.endpoint == address:
                logger.warning("Protocol error: broker received tunnel message. Possibly due to kernel bug. See: https://github.com/wlanslovenija/tunneldigger/issues/126")

        # Fall back to normal broker processing.
        return super(Broker, self).message(address, msg_type, msg_data, raw_length)
