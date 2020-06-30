#!/bin/bash
TUNNEL_ID="$1"
INTERFACE="$3"
MTU="$4"
ENDPOINT_IP="$5"
ENDPOINT_PORT="$6"
LOCAL_PORT="$7"
UUID="$8"
LOCAL_BROKER_PORT="$9"

# Remove the interface from our bridge
brctl delif digger${MTU} $INTERFACE

