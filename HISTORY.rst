v0.4.0, 2023-Aug-17
-----

* The following Linux kernel versions are supported: >= 5.10.152 5.15.76, 6.0.6, 6.1+
* Improved documentation and automated checks.
* Python 3 support.
  Python 2 is no longer supported.
  **NOTE:** If you are running the broker in a Python virtualenv you will have to
  rebuild the virtualenv using a Python 3 interpreter.
  This can be achieved by deleting the old virtualenv folder and recreating it.
  For recreating the virtualenv you can refer to the "Installation" section of
  the broker `installation chapter in the Tunneldigger documentation`_.
* Added cmake buildsystem to the client.
* Removed NAT-based handling of many client tunnels on the same server port.
  The broker now relies on the kernel properly distinguishing those UDP sockets.
* Removed dependency on Netfilter.
* Fixed compatibility with new Linux kernels on the broker side: New kernels
  force the l2tpv3 session ID to be unique system-wide, while old tunneldigger
  clients have a hard-coded ID of 1 for both ends of the tunnel. When a new
  client talks to a new broker, they will instead use a unique ID. Moreover,
  when the broker detects that it runs on an affected kernel, it reports maximal
  usage to old clients -- so if the client does usage-based selection, it will
  pick another broker.
* Improved PMTU discovery to complete more quickly after tunnel creation.
* More session and broker information is available for the hooks.
* Improve client behavior on broker failure, and decrease some reconnect
  timeouts.
* Improved and more detailed logging
* l2tp_broker.cfg confguration file changes:

  * Added option ``connection_rate_limit`` to configure the delay between two
    clients connecting.  Default is 10 (seconds), which is the limit applied
    by previous versions.  Valid values include whole seconds (10) or
    fractions of a second (0.2).  A value of 0 disables this feature.  This
    is applied per broker port.
  * Added options ``connection_rate_limit_per_ip_count`` and 
    ``connection_rate_limit_per_ip_time`` to configure a connection rate limit
    per client IP address.  If either value is 0, the functionality is disabled.
    The default values are 0. This is applied per broker port.
  * Added hook ``broker.connection-rate-limit`` which is called when the connection
    rate per IP address limit is exceeded.
  * Added option ``pmtu``, defaults to 0 (auto-discovery). If set to a non-zero
    value, this disables PMTU discovery and replying to client's PMTU discovery
    probes.
  * Removed option ``filename``. All log message are sent to STDOUT or STDERR
  * Removed option ``port_base``. No longer needed without the NAT-based
    approach
  * Removed option ``namespace``. No longer needed without the NAT-based
    approach
  * Removed option ``check_modules``. No longer implemented since v0.2.0

.. _`installation chapter in the Tunneldigger documentation`: https://tunneldigger.readthedocs.io/en/latest/server.html#installation
.. _very recent kernel: https://github.com/wlanslovenija/tunneldigger/issues/126

v0.3.0, 2017-Apr-02
-------------------

* Fixed double command bug in traffic control code.
* Added optional broker selection based on usage.
* Fixed off-by-one error in PREPARE package.
* Added tests.
* Added ``fq_codel`` ``tc`` rule to help alleviate buffer bloat.
* Added new CFFI-based conntrack bindings.
* Broker can now be installed as a Python package via ``setup.py``. Due to
  this change it is now run as ``python -m tunneldigger_broker.main l2tp_broker.cfg``
  after installation.

v0.2.0, 2015-Dec-24
-------------------

* Broker rewrite so that it can run on OpenWrt.
  The broker now enforces a 10s delay between two clients connecting.
  Support for several config options got dropped: max_cookies, tunnel_timeout, pmtu_discovery, check_modules, filename.
  Hooks run asynchronously.  In particular, the pre-down hook is not guaranteed to complete before the tunnel is shut down.
* Broker is now run as ``python -m broker.main l2tp_broker.cfg`` from the repository directory.

v0.1.0, 2015-Dec-16
-------------------

* Version with broker which does not run on OpenWrt.
