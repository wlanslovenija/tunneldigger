#!/bin/bash
TUNNEL_ID="$1"
SESSION_ID="$2"
INTERFACE="$3"
MTU="$4"
ENDPOINT_IP="$5"
ENDPOINT_PORT="$6"
LOCAL_PORT="$7"
UUID="$8"
LOCAL_BROKER_PORT="$9"

. scripts/bridge_functions.sh

# Add the interface to our bridge
ensure_bridge digger${MTU}
ip link set dev $INTERFACE master digger${MTU} mtu $MTU up

# Turn on bridge port isolation
bridge link set dev $INTERFACE isolated on
