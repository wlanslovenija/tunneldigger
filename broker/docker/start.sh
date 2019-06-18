#!/bin/bash

set -e

cd /srv/tunneldigger

cat << EOF
[broker]
; IP address the broker will listen and accept tunnels on
address=$address
; Ports where the broker will listen on
port=$port
; Interface with that IP address
interface=$interface
; Maximum number of tunnels that will be allowed by the broker
max_tunnels=$max_tunnels
; Tunnel port base. This port is not visible to clients, but must be free on the server.
; This port is used by the actual l2tp tunnel, but tunneldigger sets up NAT rules so that clients
; can keep using the control port.
port_base=$port_base
; Tunnel id base
tunnel_id_base=$tunnel_id_base
; Namespace (for running multiple brokers); note that you must also
; configure disjunct ports, and tunnel identifiers in order for
; namespacing to work
namespace=$namespace
; Reject connections if there are less than N seconds since the last connection.
; Can be less than a second (e.g., 0.1).
connection_rate_limit=$connection_rate_limit
; Set PMTU to a fixed value.  Use 0 for automatic PMTU discovery.  A non-0 value also disables
; PMTU discovery on the client side, by having the server not respond to client-side PMTU
; discovery probes.
pmtu=$pmtu

[log]
; Verbosity
verbosity=$verbosity
; Should IP addresses be logged or not
log_ip_addresses=$log_ip_addresses

[hooks]
; Note that hooks are called asynchonously!

; Arguments to the session.{up,pre-down,down} hooks are as follows:
;
;    <tunnel_id> <session_id> <interface> <mtu> <endpoint_ip> <endpoint_port> <local_port>
;
; Arguments to the session.mtu-changed hook are as follows:
;
;    <tunnel_id> <session_id> <interface> <old_mtu> <new_mtu>
;

; Called after the tunnel interface goes up
session.up=/srv/tunneldigger/tunneldigger/broker/scripts/setup_interface.sh
; Called just before the tunnel interface goes down
; (However, due to hooks being asynchonous, the hook may actually execute after the interface was
; already removed.)
session.pre-down=/srv/tunneldigger/tunneldigger/broker/scripts/teardown_interface.sh
; Called after the tunnel interface goes down
session.down=
; Called after the tunnel MTU gets changed because of PMTU discovery
session.mtu-changed=/srv/tunneldigger/tunneldigger/broker/scripts/mtu_changed.sh
EOF > /srv/tunneldigger/broker/l2tp_broker.cfg

/srv/env_tunneldigger/bin/python -m tunneldigger_broker.main /srv/tunneldigger/broker/l2tp_broker.cfg

