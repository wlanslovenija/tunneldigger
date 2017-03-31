import os


class TrafficControlError(Exception):
    pass


class TrafficControl(object):
    def __init__(self, interface):
        """
        Class constructor.

        :param interface: Name of traffic controller interface
        """

        self.interface = interface

    def tc(self, command, ignore_fails=False):
        """
        Executes a traffic control command.
        """

        if os.system('tc %s' % (command)) != 0 and not ignore_fails:
            raise TrafficControlError

    def reset(self):
        """
        Clears all existing traffic control rules.
        """

        self.tc('qdisc del dev %s root handle 1: htb default 0' % self.interface, ignore_fails=True)
        self.tc('qdisc add dev %s root handle 1: htb default 1' % self.interface)

    def set_fixed_bandwidth(self, bandwidth):
        """
        Configures a fixed bandwidth class for this interface.

        :param bandwidth: Bandwidth limit in kbps
        """

        self.tc('class add dev %s parent 1: classid 1:1 htb rate %dkbit ceil %dkbit' % (
            self.interface, bandwidth, bandwidth
        ))
        self.tc('qdisc add dev %s parent 1:1 fq_codel' % (
            self.interface
        ), True)
