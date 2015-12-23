#!/bin/sh

if [ -f /srv/tunneldigger/broker/l2tp_broker.py ]; then
  # Handle old broker version.
  cd /srv/tunneldigger/broker/
  exec /srv/env_tunneldigger/bin/python /srv/tunneldigger/broker/l2tp_broker.py /srv/tunneldigger/broker/l2tp_broker.cfg
else
  # Handle new broker version.
  cd /srv/tunneldigger
  exec /srv/env_tunneldigger/bin/python -m broker.main /srv/tunneldigger/broker/l2tp_broker.cfg
fi
