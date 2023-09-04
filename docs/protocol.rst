Tunneldigger protocol
#####################

The Tunneldigger protocol is based on L2TPv3.
Tunneldigger implementing a custom control protocol,
while user data is encapsulated as L2TPv3 specifies.
This allows to use in kernel acceleration of the data path.

The L2TPv3 is specified in `RFC3931 <https://tools.ietf.org/html/rfc3931>`_

Control packets
***************

Tunneldigger is not following RFC3931 for control messages.
Tunneldigger is only supporting the T bit in the first bit to
mark a packet as control data. All other fields of RFC3931
are ignore and have a different meaning..
All fields are encoding with network byte order.

.. packetdiag::

    {
        colwidth = 16
        node_height = 48

        0:      T
        1-7:    0
        8-23:   Magic 0x73A7
        24-31:  Version
        32-39:  Type
        40-47:  Length
        48-63:  Value
    }


* The T bit must be 1
* Version must be 1
* Type of the PDU
* Length of the value

.. _PDU types:

PDU types
^^^^^^^^^

.. csv-table:: PDU types
   :header: "Type", "Name", "Summary"

   0x00, INVALID,
   0x01, COOKIE,
   0x02, PREPARE,
   0x03, ERROR,
   0x04, TUNNEL,
   0x05, KEEPALIVE,
   0x06, PMTUD,
   0x07, PMTUD_ACK,
   0x08, REL_ACK,
   0x09, PMTU_NTFY,
   0x0a, USAGE,
   0x80, LIMIT,
