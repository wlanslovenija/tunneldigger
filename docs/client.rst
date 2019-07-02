Client Installation
===================

This document should prepare you to install and run a tunneldigger client.

Getting the Source
------------------

Tunneldigger source can be retrieved from its Github repository by running
the following command::

.. code:: shell

    git clone git://github.com/wlanslovenija/tunneldigger.git

This will give you a ``tunneldigger`` directory which contains the broker and
the client in separate directories. 

Compiling the Source
--------------------

Client code can be compiled into a stand-alone program.
You will need to install the packages ``cmake``, ``build-essential``, 
``iproute2``, ``pkg-config`` ``bison`` and ``flex`` first.

.. code:: shell

    sudo apt-get install build-essential iproute2 pkg-config curl bison flex curl

To install `libnl <http://www.linuxfromscratch.org/blfs/view/svn/basicnet/libnl.html>`_,
you can download it and build it yourself.

.. code:: shell

    mkdir libnl
    cd libnl
    curl -sL https://github.com/thom311/libnl/releases/download/libnl3_4_0/libnl-3.4.0.tar.gz | tar -zxf -
    cd *
    ./configure --prefix=/usr --sysconfdir=/etc --disable-static
    make
    sudo make install

The client executable can be compiled with the following command.

.. code:: shell

    cd tunneldigger/client
    cmake .
    make .
    sudo cp tunneldigger /usr/local/bin/tunneldigger

You can remove most of the packages after a successful installation.

Running the Tunneldigger Client
-------------------------------

Running ``/usr/local/bin/tunneldigger`` should then output the following text.

.. code:: shell

    usage: /usr/local/bin/tunneldigger [options]
       -h            this text
       -f            don't daemonize into background
       -u uuid       set UUID string
       -l ip         local IP address to bind to (default 0.0.0.0)
       -b host:port  broker hostname and port (can be specified multiple times)
       -i iface      tunnel interface name
       -I iface      force client to bind tunnel socket to a specific interface
       -s hook       hook script
       -t id         local tunnel id (default 1)
       -L limit      request broker to set downstream bandwidth limit (in kbps)
       -a            select broker based on use
       -g            select first available broker to connect to (default)
       -r            select a random broker

Using the Docker Image
----------------------

There is a docker image available from `wlanslovenija/tunneldigger-client
<https://hub.docker.com/r/wlanslovenija/tunneldigger-client>`_.
You can run it when you installed docker.

.. code:: shell

    docker run --rm -it --privileged wlanslovenija/tunneldigger-client -b <IP>:<PORT>

Replace ``<IP>`` and ``<PORT>`` with the ip and port the broker uses.

Building the Docker Image
~~~~~~~~~~~~~~~~~~~~~~~~~

You can build the docker image yourself.

.. code:: shell

    cd client
    docker build --tag wlanslovenija/tunneldigger-client .

OpenWrt Package
---------------

Currently supported way to compile and deploy a client is through an OpenWrt_
package. Source code for such OpenWrt package can be `found here`_.

.. _found here: https://github.com/wlanslovenija/firmware-packages-opkg/tree/master/net/tunneldigger
.. _OpenWrt: https://openwrt.org/

You can add the whole repository as an OpenWrt feed and add package to your firmware.

