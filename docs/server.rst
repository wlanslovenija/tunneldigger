Server (Broker) Installation
============================

The installation of Tunneldigger's server side (broker) is pretty straightforward and is
described in the following sections.

OpenWrt Package
---------------

If you want to run Tunneldigger's server side on OpenWrt_, you can use the `opkg package`_.

.. _opkg package: https://github.com/wlanslovenija/firmware-packages-opkg/tree/master/net/tunneldigger-broker
.. _OpenWrt: https://openwrt.org/

You can add the whole repository as an OpenWrt feed and add package to your firmware.

Getting the Source
------------------

If you want to run Tunneldigger from source, it can be retrieved from its GitHub
repository by running the following command::

    git clone git://github.com/wlanslovenija/tunneldigger.git

This will give you a ``tunneldigger`` directory which contains the broker
and the client in separate directories. Server installations only need
the broker.

.. warning::
    ``master`` branch is not necessary stable and you should not be using it in production.
    Instead, use the latest release. See history_ for the list of changes.

.. _history: https://github.com/wlanslovenija/tunneldigger/blob/master/HISTORY.rst

Prerequisites
-------------

The first thing you need is a recent (>= 2.6.36) Linux kernel that supports L2TPv3
tunnels. The following modules are required for Tunneldigger operation:

* ``l2tp_core``
* ``l2tp_eth``
* ``l2tp_netlink``

In addition the kernel must support network address translation via netfilter,
otherwise the tunnels will not work as Tunneldigger uses translation to achieve
that all tunnels operate over the same external port.

Also, if you want to have working bandwidth limits, the kernel must support traffic
shaping and the HTB queuing discipline, together with ``fq_codel``.

The system should be configured to load these modules at boot which is usually done
by listing the modules in ``/etc/modules``.

Also the following Debian packages are required:

* ``iproute``
* ``bridge-utils``
* ``libnetfilter-conntrack-dev``
* ``libnfnetlink-dev``
* ``libffi-dev``
* ``python-dev``
* ``libevent-dev``

If you would like to use the already supplied hook scripts to setup the network
interfaces, you also need the following packages:

* ``ebtables``

Note that the best way to run any Python software is in a virtual environment
(virtualenv_), so the versions you have installed on your base system should
not affect the versions that are installed for Tunneldigger.

.. _virtualenv: http://pypi.python.org/pypi/virtualenv

You can install all of the above simply by running on Debian::

    sudo apt-get install iproute bridge-utils libnetfilter-conntrack-dev libnfnetlink-dev libffi-dev python-dev libevent-dev ebtables python-virtualenv

and for Fedora you can use this command::

    sudo yum install iproute bridge-utils libnetfilter_conntrack python-devel libevent-devel ebtables libnl-devel python-pip python-virtualenv

Installation
------------

If we assume that you are installing Tunneldigger under ``/srv/tunneldigger``
(the scripts provided with Tunneldigger assume that as well), you can do::

    cd /srv/tunneldigger
    virtualenv env_tunneldigger

This creates the virtual environment. You can then checkout the Tunneldigger
repository into ``/srv/tunneldigger/tunneldigger`` by doing::

    cd /srv/tunneldigger
    git clone https://github.com/wlanslovenija/tunneldigger.git

Next you have to enter the environment and install the broker alongside its dependencies::

    source env_tunneldigger/bin/activate
    cd tunneldigger/broker
    python setup.py install

Configuration
-------------

The broker must be given a configuration file as first argument, an example of
which is provided in ``l2tp_broker.cfg.example``. There are some options that must be
changed and some that can be left as default:

* **address** should be configured with the external IP address that the clients will use to connect with the broker.

* **port** should be configured with the external port (or ports separated by commas) that the clients will use to connect with the broker.

* **interface** should be configured with the name of the external interface that the clients will connect to.

* Hooks in the **hooks** section should be configured with paths to executable scripts that will be called when certain events occur in the broker. They are empty by default which means that tunnels will be established but they will not be configured.

Hook scripts that actually perform interface setup. Examples that we use in
production in *wlan slovenija* network are provided under the ``scripts/``
directory. The configuration file must contain absolute paths to the hook
scripts and the scripts must have the executable bit set.

Hooks
`````

There are currently four different hooks, namely:

* ``session.up`` is called after the tunnel interface has been created by the broker and is ready for configuration at
  the higher layers (example of such a script is found under ``scripts/setup_interface.sh``)

* ``session.pre-down`` is called just before the tunnel interface is going to be removed by the broker (example is
  found under ``scripts/teardown_interface.sh``).  Notice that hooks are executed asynchonously, so by the time
  this script runs, the interface may already be gone.

* ``session.down`` is called after the tunnel interface has been destroyed and is no longer available (we currently
  do not use this hook)

* ``session.mtu-changed`` is called after the broker's path MTU discovery determines that the tunnel's MTU has changed
  and should be adjusted (example is found under ``scripts/mtu_changed.sh``)

Please look at all the example hook scripts carefully and try to understand
them before use. They should be considered configuration and some things in
them are hardcoded for our deployment. You will probably have some different
network configuration and so you should modify the scripts to suit your setup.

Example hook scripts present in the ``scripts/`` subdirectory are set up to
create one bridge device per MTU and attach L2TP interfaces to these bridges.
They also configure a default IP address to newly created tunnels, set up
``ebtables`` to isolate bridge ports and update the routing policy via ``ip
rule`` so traffic from these interfaces is routed via the ``mesh`` routing
table.

* Each tunnel established with the broker will create its own interface. Because we are using OLSRv1, we cannot
  dynamically add interfaces to it, so we group tunnel interfaces into bridges.

* We could put all tunnel interfaces into the same bridge, but this would actually create a performance problem.
  Different tunnels can have different MTU values -- but there is only one MTU value for the bridge, the minimum of
  all interfaces that are attached to that bridge. To avoid this problem, we create multiple bridges, one for each MTU
  value -- this is what the example scripts do.

* We also configure some ``ip`` policy rules to ensure that traffic coming in from the bridges gets routed via our
  ``mesh`` routing table and not the main one (see ``bridge_functions.sh``). Traffic between bridge ports is not
  forwarded (this is achieved via ``ebtables)``, otherwise the routing daemons at the nodes would think that all of
  them are directly connected -- which would cause them to incorrectly see a very large 1-hop neighbourhood. This
  file also contains broker-side IP configuration for the bridge which should really be changed.

Note that you do not actually need to have the same configuration, this is just
something that we are using at the moment in *wlan slovenija* network. The
scripts should be very flexible and you can configure them to do anything you
want/need.

Routing Daemon
''''''''''''''

The example hook scripts require that the routing daemon (like ``olsrd``) be
configured with the Tunneldigger bridge interfaces.

Running
-------

After you configured Tunneldigger, you can run the broker::

    cd /srv/tunneldigger
    /srv/env_tunneldigger/bin/python -m tunneldigger_broker.main /srv/tunneldigger/broker/l2tp_broker.cfg

Docker Image
------------

There is a docker image available from `wlanslovenija/tunneldigger-broker
<https://hub.docker.com/r/wlanslovenija/tunneldigger-broker>`_.
You can run it when you installed docker.

.. code:: shell

    docker run --rm -it --privileged wlanslovenija/tunneldigger-broker

You can configure the different values in the config file using
environment variables as shown here:

.. code:: shell

    docker run -e address=127.0.0.1 -e port=53,123,8942 \
               -e interface=lo      -e max_tunnels=1024 \
               -e port_base=20000   -e tunnel_id_base=100 \
               -e namespace=default -e connection_rate_limit=10 \
               -e pmtu=0            -e verbosity=DEBUG \
               -e log_ip_addresses=false --privileged \
               -it wlanslovenija/tunneldigger-broker

Instead of configuring the environment variables one by one
using the ``-e`` option, you can also use the ``--env-file``
option.

Build
~~~~~

You can build the docker image yourself.

.. code:: shell

    cd broker
    docker build --tag wlanslovenija/tunneldigger-broker .



