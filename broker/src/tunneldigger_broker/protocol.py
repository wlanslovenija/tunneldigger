import hashlib
import hmac
import logging
import os
import time
import struct

# Logger.
logger = logging.getLogger("tunneldigger.protocol")

# Unreliable messages (0x00 - 0x7F).
CONTROL_TYPE_INVALID   = 0x00
CONTROL_TYPE_COOKIE    = 0x01
CONTROL_TYPE_PREPARE   = 0x02
CONTROL_TYPE_ERROR     = 0x03
CONTROL_TYPE_TUNNEL    = 0x04
CONTROL_TYPE_KEEPALIVE = 0x05
CONTROL_TYPE_PMTUD     = 0x06
CONTROL_TYPE_PMTUD_ACK = 0x07
CONTROL_TYPE_REL_ACK   = 0x08
CONTROL_TYPE_PMTU_NTFY = 0x09
CONTROL_TYPE_USAGE     = 0x0A

# Reliable messages (0x80 - 0xFF).
MASK_CONTROL_TYPE_RELIABLE = 0x80
CONTROL_TYPE_LIMIT     = 0x80

# Error Reason Byte.
# e.g. a client shutdown. it sends 0x11 to the server which answer with 0x00 (other request)
# left nibble is direction
ERROR_REASON_FROM_SERVER = 0x00
ERROR_REASON_FROM_CLIENT = 0x10
# right nibble is error code
ERROR_REASON_OTHER_REQUEST  = 0x01 # other site requested
ERROR_REASON_SHUTDOWN       = 0x02 # shutdown
ERROR_REASON_TIMEOUT        = 0x03
ERROR_REASON_FAILURE        = 0x04 # e.q. on malloc() failure
ERROR_REASON_UNDEFINED      = 0x05

# Session feature flags
FEATURE_UNIQUE_SESSION_ID = 1 << 0
FEATURES_MASK = FEATURE_UNIQUE_SESSION_ID

# Limit types.
LIMIT_TYPE_BANDWIDTH_DOWN = 0x01

INVALID_MESSAGE = (CONTROL_TYPE_INVALID, '')


def parse_message(data):
    """
    Parses a tunneldigger control message.

    :param data: Raw data
    :return: A tuple (type, payload) containing the message type and payload
    """

    if len(data) < 6:
        return INVALID_MESSAGE

    # Parse header.
    magic1, magic2, version, msg_type, msg_length = struct.unpack('!BHBBB', data[0:6])
    if magic1 != 0x80 or magic2 != 0x73A7:
        return INVALID_MESSAGE

    if version != 1:
        return INVALID_MESSAGE

    try:
        return msg_type, data[6:6 + msg_length]
    except IndexError:
        return INVALID_MESSAGE

# Generate secret key.
SECRET_KEY = os.urandom(32)
# Determine epoch.
PROTOCOL_EPOCH = int(time.time()) >> 6


def protocol_time():
    """
    Returns the current time in protocol epoch.
    """

    return ((int(time.time()) >> 6) - PROTOCOL_EPOCH) % 65536


class HandshakeProtocolMixin(object):
    """
    A mixin that adds handling of the tunneldigger handshake protocol to
    a pollable class.
    """

    def message(self, address, msg_type, msg_data, raw_length):
        """
        Called when a new protocol message is received.

        :param address: Source address (host, port) tuple
        :param msg_type: Message type
        :param msg_data: Message payload
        :param raw_length: Length of the raw message (including headers)
        """

        if msg_type == CONTROL_TYPE_COOKIE:
            # Packet format:
            # 8 bytes of padding, to make sure the response is no larger than the request.
            if len(msg_data) < 8:
                return

            # Generate a random cookie as follows:
            #   2 bytes protocol time mod 65536
            #   6 bytes HMAC-SHA1 keyed with SECRET_KEY and computed
            #           over (src_host, src_port, random_bytes)
            timestamp = struct.pack('!H', protocol_time())
            signed_value = '%s%s%s' % (address[0], address[1], timestamp)
            signature = hmac.HMAC(SECRET_KEY, signed_value.encode('utf-8'), hashlib.sha1).digest()[:6]
            self.write_message(address, CONTROL_TYPE_COOKIE, timestamp + signature)
        elif msg_type == CONTROL_TYPE_PREPARE:
            # Packet format:
            # 2 bytes protocol time
            # 6 bytes "cookie", must be the signature we computed above
            # 1 byte UUID length
            # N bytes UUID
            # optionally 4 bytes remote tunnel ID
            # optionally 4 bytes client feature flags

            offset = 0

            # Verify cookie value.
            timestamp = msg_data[offset:offset + 2]
            offset += 2
            signed_value = '%s%s%s' % (address[0], address[1], timestamp)
            signature = hmac.HMAC(SECRET_KEY, signed_value.encode('utf-8'), hashlib.sha1).digest()[:6]
            timestamp = struct.unpack('!H', timestamp)[0]

            # Reject message if more than 2 protocol ticks old.  One tick is 1 >> 6 = 64 seconds.
            if signature != msg_data[offset:offset + 6] or abs(protocol_time() - timestamp) > 2:
                return
            offset += 6

            uuid_len = msg_data[offset]
            offset += 1
            uuid = msg_data[offset:offset + uuid_len].decode('utf-8')
            offset += uuid_len

            # Parse optional data
            remote_tunnel_id = 1
            client_features = 0
            try:
                remote_tunnel_id = struct.unpack('!I', msg_data[offset:offset + 4])[0]
                offset += 4
                client_features = struct.unpack('!I', msg_data[offset:offset + 4])[0]
                offset += 4
            except (struct.error, IndexError):
                pass

            if not self.create_tunnel(address, uuid, remote_tunnel_id, client_features):
                logger.warning("Failed to create tunnel (%s) while processing prepare request." % uuid)
                self.write_message(address, CONTROL_TYPE_ERROR)

            return True
        elif msg_type == CONTROL_TYPE_USAGE:
            # Packet format:
            # 8 bytes of padding, to make sure the response is no larger than the request.
            # optionally 4 bytes client feature flags
            if len(msg_data) < 8:
                return

            client_features = 0
            try:
                client_features = struct.unpack('!I', msg_data[8:8 + 4])[0]
            except (struct.error, IndexError):
                pass

            # Compute tunnel usage information.
            usage = self.get_tunnel_manager().report_usage(client_features)
            usage = struct.pack('!H', usage)
            self.write_message(address, CONTROL_TYPE_USAGE, usage)
        else:
            # Invalid message at this stage.
            return False
