#!/bin/bash
TUNNEL_ID="$1"
INTERFACE="$3"
MTU="$4"

. $(dirname $0)/bridge_functions.sh

# Set the interface to UP state
ip link set dev $INTERFACE up mtu $MTU

# Add the interface to our bridge
ensure_bridge br0
brctl addif br0 $INTERFACE

