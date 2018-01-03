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

In order to compile client code following packages are required on Ubuntu/Debian::

    build-essential pkg-config cmake libnl-genl-3-dev libnl-3-dev libasyncns-dev
    
Root permission are needed for package installation and Tunneldigger client installation.

Installation
------------

If we assume that you are currently in ``/tunneldigger/client`` folder you can do::

    cmake -G "Unix Makefiles"
    
After configuration has been succesfully built you can simply::

    make
    
After code has been compiled in order to install simply::

    sudo make install
    

OpenWrt Package
---------------

Currently supported way to compile and deploy a client is through an OpenWrt_
package. Source code for such OpenWrt package can be `found here`_.

.. _found here: https://github.com/wlanslovenija/firmware-packages-opkg/tree/master/net/tunneldigger
.. _OpenWrt: https://openwrt.org/

You can add the whole repository as an OpenWrt feed and add package to your firmware.
