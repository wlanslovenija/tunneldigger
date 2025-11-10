#!/bin/bash
TUNNEL_ID="$1"
INTERFACE="$3"
OLD_MTU="$4"
NEW_MTU="$5"

. scripts/bridge_functions.sh

# Remove interface from old bridge
ip link set dev $INTERFACE nomaster

# Change interface MTU and add to new bridge
ensure_bridge digger${NEW_MTU}
ip link set dev $INTERFACE master digger${NEW_MTU} mtu $NEW_MTU

# Turn on bridge port isolation
bridge link set dev $INTERFACE isolated on

# Bring the tunnel interface up only after port isolation is enabled
ip link set dev $INTERFACE up
