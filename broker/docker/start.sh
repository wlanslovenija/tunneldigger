#!/bin/bash

set -e

cd /srv/tunneldigger/tunneldigger/broker

#
# Check mode, see
# https://github.com/hwdsl2/docker-ipsec-vpn-server/blob/f254eacd6e081020939b568541c7c3a50663d475/run.sh#L37
#
if ip link add dummy0 type dummy 2>&1 | grep -q "not permitted"; then
  cat 1>&2 <<'  EOF'
  Error: This Docker image must be run in privileged mode.
  For detailed instructions, please visit:
  https://tunneldigger.readthedocs.io/en/latest/server.html
  EOF
  exit 1
fi
ip link delete dummy0 >/dev/null 2>&1

#
# activate modules
#

#modprobe l2tp_netlink
#modprobe l2tp_ip
#modprobe l2tp_eth
#modprobe nf_conntrack
#modprobe nf_conntrack_netlink

#
# allow forwarding
#
iptables -t nat -L
iptables -t filter -P FORWARD ACCEPT

#
# configure bridge, see
# https://github.com/wlanslovenija/tunneldigger/blob/master/tests/prepare_server.sh
#
export IP_NET="${IP_NET:-10.254.0.1/16}"
# we never use the br0 interface
#brctl addbr br0
#ip a a $IP_NET dev br0
#ip l s br0 up
# listening ip
IP=$(ip -4 -o a s dev eth0  | awk '{ print $4 }' | awk -F/ '{print $1}')


#
# Create mesh routing table, see
# https://tunneldigger.readthedocs.io/en/latest/server.html
#
echo "100     mesh" >> /etc/iproute2/rt_tables

#
# create configuration file, see
# https://github.com/wlanslovenija/tunneldigger/blob/master/broker/l2tp_broker.cfg.example
#
cat > /srv/tunneldigger/tunneldigger/broker/l2tp_broker.cfg <<EOS
[broker]
; IP address the broker will listen and accept tunnels on
address=${address:-$IP}
; Ports where the broker will listen on
port=${port:-53,123,8942}
; Interface with that IP address
interface=${interface:-eth0}
; Maximum number of tunnels that will be allowed by the broker
max_tunnels=${max_tunnels:-1024}
; Tunnel port base. This port is not visible to clients, but must be free on the server.
; This port is used by the actual l2tp tunnel, but tunneldigger sets up NAT rules so that clients
; can keep using the control port.
port_base=${port_base:-20000}
; Tunnel id base
tunnel_id_base=${tunnel_id_base:-100}
; Namespace (for running multiple brokers); note that you must also
; configure disjunct ports, and tunnel identifiers in order for
; namespacing to work
namespace=${namespace:-default}
; Reject connections if there are less than N seconds since the last connection.
; Can be less than a second (e.g., 0.1).
connection_rate_limit=${connection_rate_limit:-10}
; Set PMTU to a fixed value.  Use 0 for automatic PMTU discovery.  A non-0 value also disables
; PMTU discovery on the client side, by having the server not respond to client-side PMTU
; discovery probes.
pmtu=${pmtu:-0}

[log]
; Verbosity
verbosity=${verbosity:-DEBUG}
; Should IP addresses be logged or not
log_ip_addresses=${log_ip_addresses:-false}

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
session.up=/srv/tunneldigger/tunneldigger/broker/docker/setup_interface.sh
; Called just before the tunnel interface goes down
; (However, due to hooks being asynchonous, the hook may actually execute after the interface was
; already removed.)
session.pre-down=/srv/tunneldigger/tunneldigger/broker/scripts/teardown_interface.sh
; Called after the tunnel interface goes down
session.down=
; Called after the tunnel MTU gets changed because of PMTU discovery
session.mtu-changed=/srv/tunneldigger/tunneldigger/broker/scripts/mtu_changed.sh
EOS

#
# create the dhcp configuration
# see https://askubuntu.com/a/184351/136346
#
# IP_NET is the ip address of the broker and the netmask in the
#        form of 192.168.1.1/24
#
subnet="`docker/ip_net_to_net_mask \"$IP_NET\" | head -n 1`"
netmask="`docker/ip_net_to_net_mask \"$IP_NET\" | tail -n 1`"
subnet_bits="`echo \"$IP_NET\" | grep -Eo '[0-9]+$'`"
dhcp_start=${dhcp_start:-2}
dhcp_count=${dhcp_count:-$(( (1 << (32 - subnet_bits)) - 2 - dhcp_start ))}
dhcp_range_first="`docker/add_to_ip $subnet $dhcp_start`"
dhcp_range_last="`docker/add_to_ip $subnet $((dhcp_start + dhcp_count))`"
cat > /etc/dhcp/dhcpd.conf <<EOS
option domain-name "${domain_name:-example.org}";
option domain-name-servers ${domain_name_servers:-85.214.20.141, 194.150.168.168, 89.233.43.71};
default-lease-time ${default_lease_time:-600};
max-lease-time ${max_lease_time:-7200};
ddns-update-style ${ddns_update_style:-none};
subnet $subnet netmask $netmask {
  range $dhcp_range_first $dhcp_range_last;
}
EOS

cat > /etc/dhcp/dhclient-enter-hooks.d/no-resolv-conf <<EOS
# do not touch the resolv conf file on this computer
make_resolv_conf()
{
  return 0
}
EOS

#
# Start the service
#
/srv/tunneldigger/env_tunneldigger/bin/python -m tunneldigger_broker.main /srv/tunneldigger/tunneldigger/broker/l2tp_broker.cfg

