#!/bin/sh

HOOK=$1
DEV=$2

if [ "$HOOK" = "session.up" ] ; then
	ip a a 192.168.254.2/24 dev $DEV
	ip l s $DEV up
fi
