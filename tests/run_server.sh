#!/bin/sh

cd /srv/tunneldigger
exec /srv/env_tunneldigger/bin/python -m broker.main /srv/tunneldigger/broker/l2tp_broker.cfg
