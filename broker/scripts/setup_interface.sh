#!/bin/bash
TUNNEL_ID="$1"
INTERFACE="$3"
MTU="$4"

# Set the interface to UP state
ip link set dev $INTERFACE up

# Add the interface to our bridge
brctl addbr digger${MTU} 2>/dev/null
brctl addif digger${MTU} $INTERFACE

