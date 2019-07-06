#!/bin/sh

HOOK=$1
DEV=$2

if [ "$HOOK" = "session.up" ] ; then
	ip a a 10.254.0.3/24 dev $DEV
	ip l s $DEV up
fi
