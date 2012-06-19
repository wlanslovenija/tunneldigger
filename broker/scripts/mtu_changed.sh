#!/bin/bash
TUNNEL_ID="$1"
INTERFACE="$3"
OLD_MTU="$4"
NEW_MTU="$5"

# Remove interface from old bridge
brctl delif digger${OLD_MTU} $INTERFACE

# Add interface to new bridge
brctl addbr digger${NEW_MTU} 2>/dev/null
brctl addif digger${NEW_MTU} $INTERFACE

