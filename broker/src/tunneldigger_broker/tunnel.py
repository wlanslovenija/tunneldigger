import fcntl
import logging
import random
import socket
import struct
import time

from . import l2tp, protocol, network, limits

# Socket options.
IP_MTU_DISCOVER = 10
IP_PMTUDISC_PROBE = 3

# Ioctls.
SIOCSIFMTU = 0x8922

# Overhead of IP and UDP headers for measuring PMTU
IPV4_HDR_OVERHEAD = 28

# L2TP data header overhead for calculating tunnel MTU; takes
# the following headers into account:
#
#   20 bytes (IP header)
#    8 bytes (UDP header)
#    4 bytes (L2TPv3 Session ID)
#    4 bytes (L2TPv3 Cookie)
#    4 bytes (L2TPv3 Pseudowire CE)
#   14 bytes (Ethernet)
#
L2TP_TUN_OVERHEAD = 54

# PMTU probe sizes.
PMTU_DEFAULT = 1446
PMTU_PROBE_SIZES = [1500, 1492, 1476, 1450, 1400, 1334]
PMTU_PROBE_SIZE_COUNT = len(PMTU_PROBE_SIZES)
PMTU_PROBE_REPEATS = 4
PMTU_PROBE_COMBINATIONS = PMTU_PROBE_SIZE_COUNT * PMTU_PROBE_REPEATS

# Logger.
logger = logging.getLogger("tunneldigger.tunnel")


class TunnelSetupFailed(Exception):
    pass


class Tunnel(protocol.HandshakeProtocolMixin, network.Pollable):
    """
    A tunnel descriptor.
    """

    def __init__(self, broker, address, endpoint, uuid, tunnel_id, remote_tunnel_id, pmtu_fixed, client_features):
        """
        Construct a tunnel.

        :param broker: Broker instance that received the initial request
        :param address: Destination broker address (host, port) tuple
        :param endpoint: Remote tunnel endpoint address (host, port) tuple
        :param uuid: Unique tunnel identifier received from the remote host
        :param tunnel_id: Locally assigned tunnel identifier
        :param remote_tunnel_id: Remotely assigned tunnel identifier
        """

        super(Tunnel, self).__init__(address, broker.interface)
        self.socket.connect(endpoint)
        self.socket.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_PROBE)

        self.broker = broker
        self.endpoint = endpoint
        self.uuid = uuid
        self.client_features = client_features
        self.tunnel_id = tunnel_id
        self.remote_tunnel_id = remote_tunnel_id
        self.session_id = self.tunnel_id if self.client_features & protocol.FEATURE_UNIQUE_SESSION_ID else 1
        self.remote_session_id = self.remote_tunnel_id if self.client_features & protocol.FEATURE_UNIQUE_SESSION_ID else 1

        self.last_alive = time.time()
        self.created_time = None
        self.keepalive_seqno = 0

        # Initialize PMTU values.
        self.automatic_pmtu = pmtu_fixed == 0
        self.tunnel_mtu = PMTU_DEFAULT
        self.remote_tunnel_mtu = None
        self.measured_pmtu = PMTU_DEFAULT if self.automatic_pmtu else pmtu_fixed
        self.pmtu_probe_iteration = 0
        self.pmtu_probe_size = None
        self.pmtu_probe_acked_mtu = 0

    def get_tunnel_manager(self):
        """
        Returns the tunnel manager for this tunnel.
        """

        return self.broker.tunnel_manager

    def get_session_name(self):
        """
        Returns the interface name for a tunnel's session.
        """

        return "l2tp%d-%d" % (self.tunnel_id, self.session_id)

    def setup_tunnel(self):
        """
        Initializes the tunnel.
        """

        # Make the UDP socket an encapsulation socket by asking the kernel to do so.
        try:
            self.broker.netlink.tunnel_create(self.tunnel_id, self.remote_tunnel_id, self.socket.fileno())

            # Create a pseudowire L2TP session over the tunnel.
            self.broker.netlink.session_create(self.tunnel_id, self.session_id, self.remote_session_id, self.get_session_name())
        except l2tp.L2TPTunnelExists:
            self.socket.close()
            raise
        except l2tp.L2TPSessionExists:
            self.socket.close()
            raise
        except l2tp.NetlinkError:
            self.socket.close()
            raise TunnelSetupFailed

        self.created_time = time.time()

        # Respond with tunnel establishment message.
        server_features = self.client_features & protocol.FEATURES_MASK
        if server_features:
            # Tell the client which features we support.
            msg = struct.pack('!II', self.tunnel_id, server_features)
        else:
            # There are no features to speak of.
            msg = struct.pack('!I', self.tunnel_id)
        self.write_message(self.endpoint, protocol.CONTROL_TYPE_TUNNEL, msg)

        # Spawn keepalive timer.
        self.create_timer(self.keepalive, timeout=random.randrange(3, 15), interval=5)
        # Spawn PMTU measurement timer. The initial timeout is randomized to avoid all tunnels
        # from starting the measurements at the same time.
        self.create_timer(self.pmtu_discovery, timeout=random.randrange(5, 30))

        # Update MTU.
        self.update_mtu(initial=True)

        # Call session up hook.
        self.broker.hook_manager.run_hook(
            'session.up',
            self.tunnel_id,
            self.session_id,
            self.get_session_name(),
            self.tunnel_mtu,
            self.endpoint[0],
            self.endpoint[1],
            self.address[1],
            self.uuid,
            self.broker.address[1],
        )

    def pmtu_discovery(self):
        """
        Handle periodic PMTU discovery.
        """
        if not self.automatic_pmtu:
            # Send our static MTU, and do not renew timer (so we never repeat this).
            self.write_message(self.endpoint, protocol.CONTROL_TYPE_PMTU_NTFY, struct.pack('!H', self.measured_pmtu))
            return

        if self.pmtu_probe_size is not None and self.pmtu_probe_size <= self.pmtu_probe_acked_mtu:
            # No need to check lower PMTUs as we already received acknowledgement. Restart
            # PMTU discovery after sleeping for some time.
            self.pmtu_probe_iteration = 0
            self.pmtu_probe_size = None
            self.pmtu_probe_acked_mtu = 0
            self.create_timer(self.pmtu_discovery, timeout=random.randrange(500, 700))
            return

        self.pmtu_probe_size = PMTU_PROBE_SIZES[int(self.pmtu_probe_iteration / PMTU_PROBE_REPEATS)]
        self.pmtu_probe_iteration = (self.pmtu_probe_iteration + 1) % PMTU_PROBE_COMBINATIONS

        # Transmit the PMTU probe.
        probe = b'\x80\x73\xA7\x01\x06\x00'
        probe += b'\x00' * (self.pmtu_probe_size - IPV4_HDR_OVERHEAD - len(probe))
        self.write(self.endpoint, probe)

        # Wait some to get the reply.
        self.create_timer(self.pmtu_discovery, timeout=random.randrange(2, 5))

    def update_mtu(self, initial=False):
        """
        Updates the tunnel MTU from self.measured_pmtu.
        """

        detected_pmtu = max(1280, min(self.measured_pmtu, self.remote_tunnel_mtu or PMTU_DEFAULT))
        if not initial and detected_pmtu == self.tunnel_mtu:
            return

        old_tunnel_mtu = self.tunnel_mtu
        self.tunnel_mtu = detected_pmtu
        logger.info("Set tunnel %d MTU to %d." % (self.tunnel_id, detected_pmtu))

        # Alter tunnel MTU.
        try:
            interface_name = (self.get_session_name().encode('utf-8') + b'\x00' * 16)[:16]
            data = struct.pack("16si", interface_name, self.tunnel_mtu)
            fcntl.ioctl(self.socket, SIOCSIFMTU, data)
        except IOError:
            logger.warning("Failed to set MTU for tunnel %d! Is the interface down?" % self.tunnel_id)

        self.broker.netlink.session_modify(self.tunnel_id, self.session_id, self.tunnel_mtu)

        if not initial:
            # Run MTU changed hook.
            self.broker.hook_manager.run_hook(
                'session.mtu-changed',
                self.tunnel_id,
                self.session_id,
                self.get_session_name(),
                old_tunnel_mtu,
                self.tunnel_mtu,
                self.uuid,
            )

    def keepalive(self):
        """
        Handle periodic keepalives.
        """

        # Transmit keepalive message. The sequence number is needed because some ISPs (usually cable
        # or mobile operators) do some "optimisation" and drop udp packets containing the same content.
        self.write_message(self.endpoint, protocol.CONTROL_TYPE_KEEPALIVE, struct.pack('!H', self.keepalive_seqno))
        self.keepalive_seqno = (self.keepalive_seqno + 1) % 65536

        # Check if the tunnel is still alive.
        if time.time() - self.last_alive > 120:
            logger.warning("Tunnel %d (%s) timed out", self.tunnel_id, self.uuid)
            self.close(reason=protocol.ERROR_REASON_FROM_SERVER | protocol.ERROR_REASON_TIMEOUT)

    def close(self, reason=protocol.ERROR_REASON_UNDEFINED):
        """
        Closes the tunnel.

        :param reason: Reason code for the tunnel being closed
        """

        logger.info("Closing tunnel %d (%s) after %d seconds", self.tunnel_id, self.uuid, time.time() - self.created_time)

        # Run pre-down hook.
        self.broker.hook_manager.run_hook(
            'session.pre-down',
            self.tunnel_id,
            self.session_id,
            self.get_session_name(),
            self.tunnel_mtu,
            self.endpoint[0],
            self.endpoint[1],
            self.address[1],
            self.uuid,
            self.broker.address[1],
        )

        self.broker.netlink.session_delete(self.tunnel_id, self.session_id)

        # Run down hook.
        self.broker.hook_manager.run_hook(
            'session.down',
            self.tunnel_id,
            self.session_id,
            self.get_session_name(),
            self.tunnel_mtu,
            self.endpoint[0],
            self.endpoint[1],
            self.address[1],
            self.uuid,
            self.broker.address[1],
        )

        # Transmit error message so the other end can tear down the tunnel
        # immediately instead of waiting for keepalive timeout.
        self.write_message(self.endpoint, protocol.CONTROL_TYPE_ERROR, bytearray([reason]))

        super(Tunnel, self).close()

        self.broker.tunnel_manager.destroy_tunnel(self)

    def create_tunnel(self, address, uuid, remote_tunnel_id, client_features):
        """
        The tunnel may receive a valid create tunnel message in case our previous
        response has been lost. In this case, we just need to reply with an identical
        control message.
        """

        if uuid != self.uuid:
            logger.warning("Protocol error: tunnel UUID has changed.")
            return False

        if remote_tunnel_id != self.remote_tunnel_id:
            logger.warning("Protocol error: tunnel identifier has changed.")
            return False

        if client_features != self.client_features:
            logger.warning("Protocol error: client features have changed.")
            return False

        # Respond with tunnel establishment message.
        self.write_message(self.endpoint, protocol.CONTROL_TYPE_TUNNEL, struct.pack('!I', self.tunnel_id))

        return True

    def message(self, address, msg_type, msg_data, raw_length):
        """
        Called when a new protocol message is received.

        :param address: Source address (host, port) tuple
        :param msg_type: Message type
        :param msg_data: Message payload
        :param raw_length: Length of the raw message (including headers)
        """

        if address != self.endpoint:
            logger.warning("Protocol error: tunnel endpoint has changed. Possibly due to kernel bug. See: https://github.com/wlanslovenija/tunneldigger/issues/126")
            return False

        if super(Tunnel, self).message(address, msg_type, msg_data, raw_length):
            return True

        # Update keepalive indicator.
        self.last_alive = time.time()

        if msg_type == protocol.CONTROL_TYPE_ERROR:
            # Error notification from the remote side.
            # TODO: Parse error code.
            self.close(reason=protocol.ERROR_REASON_FROM_SERVER | protocol.ERROR_REASON_OTHER_REQUEST)
            return True
        elif msg_type == protocol.CONTROL_TYPE_PMTUD:
            # The other side is performing PMTU discovery.  Only cooperate if automatic MTU discovery is
            # enabled for this network.
            pmtu_probe = struct.pack('!H', raw_length)
            if self.automatic_pmtu:
                self.write_message(self.endpoint, protocol.CONTROL_TYPE_PMTUD_ACK, pmtu_probe)
            return True
        elif msg_type == protocol.CONTROL_TYPE_PMTUD_ACK:
            # The other side is acknowledging a specific PMTU value.
            pmtu = struct.unpack('!H', msg_data)[0] + IPV4_HDR_OVERHEAD
            if self.automatic_pmtu and pmtu > self.pmtu_probe_acked_mtu:
                self.pmtu_probe_acked_mtu = pmtu
                self.measured_pmtu = pmtu - L2TP_TUN_OVERHEAD
                self.update_mtu()

                # Notify the other side of our measured MTU.
                self.write_message(self.endpoint, protocol.CONTROL_TYPE_PMTU_NTFY, struct.pack('!H', self.measured_pmtu))

            return True
        elif msg_type == protocol.CONTROL_TYPE_PMTU_NTFY:
            # The other side is notifying us about their tunnel MTU.
            remote_mtu = struct.unpack('!H', msg_data)[0]

            if self.automatic_pmtu and remote_mtu != self.remote_tunnel_mtu:
                self.remote_tunnel_mtu = remote_mtu
                self.update_mtu()

            return True
        elif msg_type & protocol.MASK_CONTROL_TYPE_RELIABLE:
            # Acknowledge reliable control messages.
            self.write_message(self.endpoint, protocol.CONTROL_TYPE_REL_ACK, msg_data[:2])

            if msg_type == protocol.CONTROL_TYPE_LIMIT:
                # Client requests limit configuration.
                limit_manager = limits.LimitManager(self)
                limit_manager.configure(msg_data[2:])
                return True

        return False
