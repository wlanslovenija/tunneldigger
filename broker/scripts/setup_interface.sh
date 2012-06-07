#!/bin/bash
TUNNEL_ID="$1"
INTERFACE="$3"

# Set the interface to UP state
/sbin/ip link set dev $INTERFACE up

# Add the interface to our bridge
/usr/sbin/brctl addif digger0 $INTERFACE

