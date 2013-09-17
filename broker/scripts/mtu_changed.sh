#!/bin/bash
TUNNEL_ID="$1"
INTERFACE="$3"
OLD_MTU="$4"
NEW_MTU="$5"

. scripts/bridge_functions.sh

# Remove interface from old bridge
brctl delif digger${OLD_MTU} $INTERFACE

# Change interface MTU
ip link set dev $INTERFACE mtu $NEW_MTU

# Add interface to new bridge
ensure_bridge digger${NEW_MTU}
brctl addif digger${NEW_MTU} $INTERFACE

