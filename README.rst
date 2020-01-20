Tunneldigger
============

L2TPv3 VPN tunneling solution

.. image:: https://travis-ci.org/wlanslovenija/tunneldigger.svg?branch=master
    :target: https://travis-ci.org/wlanslovenija/tunneldigger

About
-----

Tunneldigger is one of the projects of `wlan slovenija`_ open wireless network.
It is a simple VPN tunneling solution based on L2TPv3 tunnels supported in
recent Linux kernels.

.. _wlan slovenija: https://wlan-si.net

It consists of a client and a server portion referred to as the broker. The
client is optimized to run on embedded devices such as wireless routers
running OpenWrt_.

.. _OpenWrt: https://openwrt.org

The client is written in C to allow for smaller binary size whereas the server
portion, referred to as the broker, is written in Python.

Installation and Use
--------------------

Information on set up and use of Tunneldigger can be found in the
documentation:

https://tunneldigger.readthedocs.org/

Source Code and Issue Tracker
-------------------------------------------

Development happens on GitHub_ and issues can be filed in the `Issue tracker`_.

.. _GitHub: https://github.com/wlanslovenija/tunneldigger
.. _Issue tracker: https://github.com/wlanslovenija/tunneldigger/issues

License
-------

Tunneldigger is licensed under AGPLv3_.

.. _AGPLv3: https://www.gnu.org/licenses/agpl-3.0.en.html

Contributions
-------------

We welcome code and documentation contributions to Tunneldigger in the form of
`Pull Requests`_ on GitHub where they can be reviewed and discussed by the
community.
We encourage everyone to check out any pending pull requests and offer comments
or ideas as well.

.. _Pull Requests: https://github.com/wlanslovenija/tunneldigger/pulls

Tunneldigger is developed by a community of developers from many different
backgrounds.

You can visualize all code contributions using `GitHub Insights`_.

.. _GitHub Insights: https://github.com/wlanslovenija/tunneldigger/graphs/contributors
