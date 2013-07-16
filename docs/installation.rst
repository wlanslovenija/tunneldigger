Installation
============

The installation of tunneldigger is pretty straightforward and is described
in the following sections.

Getting the Source
------------------

Tunneldigger source can be retrieved from its Github repository by running
the following command::

    git clone git://github.com/wlanslovenija/tunneldigger.git

This will give you a ``tunneldigger`` directory which contains the broker
and the client in separate directories. Server installations only need
the broker.

Prerequisites
-------------

The first thing you need is a recent (>= 2.6.36) Linux kernel that supports L2TPv3
tunnels. The following modules are required for tunneldigger operation:

* l2tp_core
* l2tp_eth
* l2tp_netlink

In addition the kernel must support network address translation via netfilter,
otherwise the tunnels will not work as tunneldigger uses translation to achieve
that all tunnels operate over the same external port.

Also, if you want to have working bandwidth limits, the kernel must support traffic
shaping and the HTB queuing discipline.

The system should be configured to load these modules at boot which is usually done
by listing the modules in ``/etc/modules``.

Also the following Debian packages are required:

* iproute
* bridge-utils
* libnetfilter-conntrack3
* python-dev
* libevent-dev

If you would like to use the already supplied hook scripts to setup the network
interfaces, you also need the following packages:

* ebtables

You can install all of the above simply by running on Debian::

    sudo apt-get install iproute bridge-utils libnetfilter-conntrack3 python-dev libevent-dev ebtables

and for Fedora you can use this command::

    sudo yum install iproute bridge-utils libnetfilter_conntrack python-devel libevent-devel ebtables libnl-devel python-pip

There are also some Python modules required, all of them are listed in the 
``requirements.txt`` file that is included in the tunneldigger distribution. You
can install all of them (after you have already installed the above Debian packages) with
the use of ``pip`` as follows::

    sudo pip install -r requirements.txt

Configuration
-------------

The broker must be given a configuration file as first argument, an example of
which is provided in ``l2tp_broker.cfg``. There are some options that must be
changed and some that can be left as default:

* **address** should be configured with the external IP address that the clients will use to connect with the broker.

* **port** should be configured with the external port (or ports separated by commas) that the clients will use to connect with the broker.

* **interface** should be configured with the name of the external interface that the clients will connect to.

* Hooks in the **hooks** section should be configured with paths to executable scripts that will be called when certain events ocurr in the broker. Some scripts are already bundled with the broker in the ``scripts/`` subdirectory.

Hooks
`````

Example hook scripts present in the ``scripts/`` subdirectory are set up to
create one bridge device per MTU and attach L2TP interfaces to these bridges.
They also configure a default IP address to newly created tunnels, set up
``ebtables`` to isolate bridge ports and update the routing policy via ``ip rule``
so traffic from these interfaces is routed via the ``mesh`` routing table.

You will probably have some different network configuration and so you should modify
the scripts to suit your setup.

Routing Daemon
''''''''''''''

The example hook scripts require that the routing daemon (like ``olsrd``) be
configured with the tunneldigger bridge interfaces.

