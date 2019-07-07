#!/bin/bash

. scripts/setup_interface.sh
. docker/bridge_functions.sh

add_to_dhcp_server digger${MTU}

