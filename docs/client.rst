Client Installation
===================

Getting the Source
------------------

Tunneldigger source can be retrieved from its Github repository by running
the following command::

    git clone git://github.com/wlanslovenija/tunneldigger.git

This will give you a ``tunneldigger`` directory which contains the broker and
the client in separate directories. Client code can be compiled into a
stand-alone program.

OpenWrt Package
---------------

Currently supported way to compile and deploy a client is through an OpenWrt_
package. Source code for such OpenWrt package can be `found here`_.

.. _found here: https://github.com/wlanslovenija/firmware-packages-opkg/tree/master/net/tunneldigger
.. _OpenWrt: https://openwrt.org/

You can add the whole repository as an OpenWrt feed and add package to your firmware.

Configuration
-------------

* **MAX_BROKERS** (default: 10): Maximum number of brokers that can be handled in a single process.

    make CFLAGS="-D MAX_BROKERS=20"
