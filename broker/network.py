import os
import errno
import timerfd
import logging
import traceback
import select
import socket
import struct

from . import protocol

# Socket options.
SO_BINDTODEVICE = 25

# Logger.
logger = logging.getLogger("tunneldigger.network")


class PollableNotRegistered(Exception):
    pass


class Pollable(object):
    """
    Wrapper around a UDP socket interface, which may be polled by the simple
    event loop.
    """

    def __init__(self, address, interface):
        """
        Constructs a new pollable instance.

        :param address: Address (host, port) tuple to bind to
        :param interface: Interface name to bind to
        """

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(address)
        self.socket.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, interface)

        self.address = address
        self.interface = interface
        self.poller = None
        self.pollables = None
        self.timers = set()

    def register(self, poller, pollables):
        """
        Registers the pollable into the event loop.

        :param poller: Event loop poller object
        :param pollables: Event loop pollables dictionary
        """

        poller.register(self.socket, select.EPOLLIN)
        pollables[self.socket.fileno()] = self

        self.poller = poller
        self.pollables = pollables

    def close(self):
        """
        Closes the underlying socket and stops all timers.
        """

        self.socket.close()

        for timer in self.timers.copy():
            timer.close()

    def create_timer(self, callback, timeout=None, interval=None):
        """
        Creates a timer.

        :param callback: Callback to fire on timeout
        :param timeout: Delay before timer fires first
        :param interval: Interval for repeating timers
        :return: Timer object, which may be used to stop the timer
        """

        if not self.poller or not self.pollables:
            raise PollableNotRegistered

        if interval is not None and timeout is None:
            timeout = interval

        timer = timerfd.create(timerfd.CLOCK_MONOTONIC)
        timerfd.settime(timer, 0, timerfd.itimerspec(value=timeout, interval=interval))

        class Timer(object):
            def read(timer_self):
                try:
                    if not os.read(timer, timerfd.bufsize):
                        return timer_self.close()
                except OSError as e:
                    if e.args[0] in (errno.EINTR, errno.EAGAIN):
                        return

                    raise

                try:
                    callback()
                finally:
                    # Unregister the timer if it is a one-shot timer.
                    if interval is None:
                        timer_self.close()

            def close(timer_self):
                self.poller.unregister(timer)
                del self.pollables[timer]
                self.timers.remove(timer_self)
                os.close(timer)

        handler = Timer()
        self.poller.register(timer, select.EPOLLIN)
        self.pollables[timer] = handler
        self.timers.add(handler)
        return handler

    def write(self, address, data):
        """
        Writes into the underlying UDP socket.

        :param address: Destination address (host, port) tuple
        :param data: Data to write to the socket
        """

        try:
            self.socket.sendto(data, address)
        except socket.error:
            return

    def write_message(self, address, msg_type, msg_data=''):
        """
        Writes a protocol message into the underlying UDP socket.

        :param address: Destination address (host, port) tuple
        :param msg_type: Message type
        :param msg_data: Message payload (at most 254 bytes)
        """

        assert len(msg_data) < 255

        data = '\x80\x73\xA7\x01'
        data += struct.pack('!BB', msg_type, len(msg_data))
        data += msg_data

        self.write(address, data)

    def read(self):
        """
        Called by the event loop when there is new data to be read
        from the socket.
        """

        try:
            data, address = self.socket.recvfrom(2048)
        except socket.error:
            return

        msg_type, msg_data = protocol.parse_message(data)
        if msg_type == protocol.CONTROL_TYPE_INVALID:
            return

        try:
            self.message(address, msg_type, msg_data, len(data))
        except KeyboardInterrupt:
            raise
        except:
            logger.error("Unhandled exception during message processing.")
            logger.debug(traceback.format_exc())

    def message(self, address, msg_type, msg_data, raw_length):
        """
        Called when a new protocol message is received.

        :param address: Source address (host, port) tuple
        :param msg_type: Message type
        :param msg_data: Message payload
        :param raw_length: Length of the raw message (including headers)
        """

        return False
