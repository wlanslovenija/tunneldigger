import logging
import struct

from . import protocol, traffic_control

# Logger.
logger = logging.getLogger("tunneldigger.limits")


class LimitManager(object):
    """
    Tunnel traffic limit manager.
    """

    def __init__(self, tunnel, session_id):
        """
        Class constructor.

        :param tunnel: Tunnel instance
        :parma session_id: Session identifier
        """

        self.tunnel = tunnel
        self.session_id = session_id

    def configure(self, limit_message):
        """
        Configures a specific limit.

        :param limit_message: Received limit control message
        """

        try:
            limit_type, config_len = struct.unpack('!BB', limit_message[:2])
        except ValueError:
            logger.warning("Malformed limit configuration received on tunnel %d." % self.tunnel.tunnel_id)
            return False

        if limit_type == protocol.LIMIT_TYPE_BANDWIDTH_DOWN:
            # Downstream (client-wise) limit setup.
            try:
                bandwidth = struct.unpack('!I', limit_message[2:2 + config_len])[0]
            except ValueError:
                logger.warning("Malformed bandwidth limit configuration received on tunnel %d." % self.tunnel.tunnel_id)
                return False

            logger.info("Setting downstream bandwidth limit to %d kbps on tunnel %d." % (bandwidth, self.tunnel.tunnel_id))

            # Setup bandwidth limit using Linux traffic shaping.
            try:
                tc = traffic_control.TrafficControl(self.tunnel.get_session_name(self.session_id))
                tc.reset()
                tc.set_fixed_bandwidth(bandwidth)
            except traffic_control.TrafficControlError:
                logger.warning("Unable to configure traffic shaping for tunnel %d." % self.tunnel.tunnel_id)

            return True
        else:
            return False
