Capturing and analysing tunneldigger packets
############################################

Example pcap filter using tcpdump
*********************************

See :ref:`PDU types`

capture control traffic
^^^^^^^^^^^^^^^^^^^^^^^

.. code:: sh

   # capture all tunneldigger control traffic
   tcpdump -i eth0 -w /tmp/output.pcap 'udp port 8942 and udp[8] == 0x80'

capture only USAGE packets
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: sh

   # capture only USAGE packets
   tcpdump -i eth0 -w /tmp/output.pcap 'udp port 8942 and udp[8] == 0x80 and udp[12] == 0x0a'

capture control packets except KEEPALIVE, PMTUD, PMTUD_ACK, PMTUD_NTFY
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: sh

   # capture control packets except KEEPALIVE, PMTUD, PMTUD_ACK, PMTUD_NTFY
   tcpdump -i eth0 -w /tmp/output.pcap 'udp port 8942 and udp[8] == 0x80 and (udp[12] != 5 && udp[12] != 6 && udp[12] != 7 && udp[12] != 9)'


Using wireshark
***************

There is a `custom dissector <https://github.com/wlanslovenija/tunneldigger/blob/master/docs/wireshark-tunneldigger.lua>`_ for tunneldigger written in lua. The dissector is registered as **TD**.

To use the wireshark dissector call wireshark with:

.. code:: sh

   cd tunneldigger/docs/
   wireshark -Xlua_script:wireshark-tunneldigger.lua

Wireshark might decode the user data as a different protocol (e.g. Cisco HDLC). This can be changed by:

* Click on "wrong" protocol in "Packet Details" pane (usually the pane in the middle).
* Right mouse click, select **Decode As** (Ctrl-Shift-U).
* A new window with decodes should open
* A new row should be already created. The field should be called **L2TPv3 payload type**.
* Select **Ethernet** in the **Current** column.
