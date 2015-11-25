#!/bin/sh

# checkout the repo
cd /srv
git clone /git_repo tunneldigger
cd /srv/tunneldigger
git checkout "$1"

# setup bridge
brctl addbr br0
ip a a 192.168.254.1/24 dev br0
ip l s br0 up

# listening ip
IP=$(ip -4 -o a s dev eth1  | awk '{ print $4 }' | awk -F/ '{print $1}')

# setup http server
cat > /tmp/lighttpd.conf <<EOF
server.modules = (
        "mod_access",
	)

server.document-root        = "/testing/test-data"
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
virtualenv env_tunneldigger

. /srv/env_tunneldigger/bin/activate
pip install -r /srv/tunneldigger/broker/requirements.txt

# configure tunneldigger
# dont let cp fail when using an older version of tunneldigger
cp /srv/tunneldigger/broker/l2tp_broker.cfg.example /srv/tunneldigger/broker/l2tp_broker.cfg || true
sed -i "s/127.0.0.1/$IP/g" /srv/tunneldigger/broker/l2tp_broker.cfg
sed -i "s/^interface=.*/interface=eth1/g" /srv/tunneldigger/broker/l2tp_broker.cfg

# WARNING hookpath must be without a leading slash!!!
HOOKPATH=/testing/hook_server
sed -i "s!^session.up=.*!session.up=$HOOKPATH/setup_interface.sh!g" /srv/tunneldigger/broker/l2tp_broker.cfg
sed -i "s!^session.down=.*!session.down=$HOOKPATH/teardown_interface.sh!g" /srv/tunneldigger/broker/l2tp_broker.cfg
