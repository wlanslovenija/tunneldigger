vNEXT
-----

v0.3.0, 2017-Apr-02
-------------------

* Fixed double command bug in traffic control code.
* Added optional broker selection based on usage.
* Fixed off-by-one error in PREPARE package.
* Added tests.
* Added ``fq_codel`` ``tc`` rule to help alleviate buffer bloat.

v0.2.0, 2015-Dec-24
-------------------

* Broker rewrite so that it can run on OpenWrt.
* Broker is now run as ``python -m broker.main l2tp_broker.cfg`` from the repository directory.

v0.1.0, 2015-Dec-16
-------------------

* Version with broker which does not run on OpenWrt.
