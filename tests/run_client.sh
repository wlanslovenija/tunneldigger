#!/bin/sh

SERVERS=""
for srv in $@ ; do
	SERVERS=" -b $srv $SERVERS"
done

cd /srv/tunneldigger/client
exec /srv/tunneldigger/client/l2tp_client -u foobar -i l2tp0 -t 2 $SERVERS -L 102400 -s /testing/hook_client.sh -f
