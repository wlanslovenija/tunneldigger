#!/bin/sh
#
# arguments must contain a server like '-b 127.0.0.1:8942'
# but it could also contains additional arguments like '-a'

cd /srv/tunneldigger/client
exec /srv/tunneldigger/client/l2tp_client -u foobar -i l2tp0 -t 2 $SERVERS -L 102400 -s /testing/hook_client.sh -f $@
