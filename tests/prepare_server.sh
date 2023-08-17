#!/bin/sh

# checkout the repo
cd /srv
git clone /git_repo tunneldigger
cd /srv/tunneldigger
git checkout "$1"

# setup bridge
# 192.168.254.1 is the hard-coded IP of each server inside the tunnel
brctl addbr br0
ip a a 192.168.254.1/24 dev br0
ip l s br0 up

# determine listening ip (picked by setup_module in test_nose.py)
echo "This should show eth0 and eth1:"
ip addr
echo
# can't hard-code this; for usage tests we have servers in different IPs!
IP=$(ip -4 -o a s dev eth1  | awk '{ print $4 }' | awk -F/ '{print $1}')

# setup http server
cat > /tmp/lighttpd.conf <<EOF
server.modules = (
        "mod_access",
	)

server.document-root        = "/"
server.errorlog             = "/var/log/lighttpd/error.log"
server.pid-file             = "/var/run/lighttpd.pid"
server.username             = "www-data"
server.groupname            = "www-data"
server.bind                 = "192.168.254.1"
server.port                 = 8080
index-file.names            = ( "index.php", "index.html", "index.lighttpd.html" )
EOF

# start http server
lighttpd -f /tmp/lighttpd.conf
# url is http://192.168.254.1:8080/

# setup virtualenv
cd /srv/
if grep -Fq 'Python :: 3 :: Only' /srv/tunneldigger/broker/setup.py; then
    virtualenv -p /usr/bin/python3 env_tunneldigger
else
    virtualenv -p /usr/bin/python2 env_tunneldigger
fi

. /srv/env_tunneldigger/bin/activate
if [ -f /srv/tunneldigger/broker/setup.py ]; then
    pip install /srv/tunneldigger/broker
else
    pip install -r /srv/tunneldigger/broker/requirements.txt
fi

# configure tunneldigger
# dont let cp fail when using an older version of tunneldigger
cp /srv/tunneldigger/broker/l2tp_broker.cfg.example /srv/tunneldigger/broker/l2tp_broker.cfg || true
sed -i "s/^address=.*/address=$IP/" /srv/tunneldigger/broker/l2tp_broker.cfg
sed -i "s/^interface=.*/interface=eth1/" /srv/tunneldigger/broker/l2tp_broker.cfg

# save the ip into a file where the http server can access it
echo -n "$IP" > /ip.txt

# WARNING hookpath must be without a leading slash!!!
HOOKPATH=/testing/hook_server
sed -i "s!^session.up=.*!session.up=$HOOKPATH/setup_interface.sh!" /srv/tunneldigger/broker/l2tp_broker.cfg
sed -i "s!^session.down=.*!session.down=$HOOKPATH/teardown_interface.sh!" /srv/tunneldigger/broker/l2tp_broker.cfg

if [ -f /srv/tunneldigger/broker/l2tp_broker.py ]; then
    # old servers have a module check that is broken with current Ubuntu kernels, so we have to disable it.
    if grep check_modules /srv/tunneldigger/broker/l2tp_broker.cfg -q; then
        # sometimes that's easy, we can just sed the config.
        sed -i 's/check_modules=true/check_modules=false/' /srv/tunneldigger/broker/l2tp_broker.cfg
    else
        # but real old servers don't even have that config, we need to patch the source instead. ouch.
        sed -i 's/if not check_for_modules():/if False:/' /srv/tunneldigger/broker/l2tp_broker.py
    fi
fi
