#!/bin/bash
TUNNEL_ID="$1"
INTERFACE="$3"

# Remove the interface from our bridge
/usr/sbin/brctl delif digger0 $INTERFACE

