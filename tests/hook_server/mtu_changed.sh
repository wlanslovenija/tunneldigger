#!/bin/bash
TUNNEL_ID="$1"
INTERFACE="$3"
OLD_MTU="$4"
NEW_MTU="$5"

. $(dirname $0)/bridge_functions.sh

# Remove interface from old bridge
brctl delif br0 $INTERFACE

# Change interface MTU
ip link set dev $INTERFACE mtu $NEW_MTU

# Add interface to new bridge
ensure_bridge br0
brctl addif br0 $INTERFACE

