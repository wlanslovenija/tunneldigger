vNEXT
-----

* Python 3 support.
  Python 2 is no longer supported.
  **NOTE:** If you are running the broker in a Python virtualenv you will have to
  rebuild the virtualenv using a Python 3 interpreter.
  This can be achieved by deleting the old virtualenv folder and recreating it.
  For recreating the virtualenv you can refer to the "Installation" section of
  the broker `installation chapter in the Tunneldigger documentation`_.
* Fixed compatibility with new Linux kernels on the broker side: New kernels
  force the l2tpv3 session ID to be unique system-wide, while old tunneldigger
  clients have a hard-coded ID of 1 for both ends of the tunnel. When a new
  client talks to a new broker, they will instead use a unique ID. Moreover,
  when the broker detects that it runs on an affected kernel, it reports maximal
  usage to old clients -- so if the client does usage-based selection, it will
  pick another broker.
* Added cmake buildsystem to the client.
* Added option `connection_rate_limit` to configure the delay between two
  clients connecting.  Default is 10 (seconds).
* Added option `pmtu`, defaults to 0 (auto-discovery). If set to a non-zero
  value, this disables PMTU discovery and replying to client's PMTU discovery
  probes.
* Improve client behavior on broker failure, and decrease some reconnect
  timeouts.

.. _`installation chapter in the Tunneldigger documentation`: https://tunneldigger.readthedocs.io/en/latest/server.html#installation

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
