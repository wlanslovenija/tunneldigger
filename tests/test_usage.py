#!/usr/bin/env python
# This tests the current client against two servers. One already has a client connected so we make
# sure to connect to the other.
# We can no longer test against a server without support for "usage" since those
# servers just don't run on today's OSes any more (the old Python conntrack bindings broke).

import os
import tunneldigger
from tunneldigger import LOG, check_if_git_contains, run_server, run_client, run_as_lxc

OLD_REV = 'v0.3.0'

class TestClientUsage(object):
    def test_usage(self):
        """
        - we need to check if the client version is fresh enought to support usage. otherwise SKIP
        - setup server A with usage version but one client
        - setup server B with usage version without any client
        - setup server C with non-usage version

        - start client conf ABC and check if it's connecting to server B
        - start client conf AB and check if it's connecting to server B
        """
        CONTEXT = tunneldigger.get_random_context()

        bridge_name = "br-%s" % CONTEXT
        tunneldigger.create_bridge(bridge_name)

        cont_client = tunneldigger.prepare('client', CONTEXT + '_usage_client', os.environ['CLIENT_REV'], bridge_name, '172.16.16.2/24')

        servers = ['172.16.16.100', '172.16.16.101']
        cont_first = tunneldigger.prepare('server', CONTEXT + '_first_server', os.environ['CLIENT_REV'], bridge_name, servers[0]+'/24')
        cont_second = tunneldigger.prepare('server', CONTEXT + '_second_server', OLD_REV, bridge_name, servers[1]+'/24')
        cont_all_servers = [cont_first, cont_second]

        cont_dummy_client = tunneldigger.prepare('client', CONTEXT + '_dummy_client', os.environ['CLIENT_REV'],
                                                 bridge_name, '172.16.16.1/24')
        cont_all_clients = [cont_dummy_client, cont_client]

        LOG("Created servers {}".format([x.name for x in cont_all_servers]))
        LOG("Created clients {}".format([x.name for x in cont_all_clients]))

        # start all servers
        pids_all_servers = [run_server(x) for x in cont_all_servers]
        pid_dummy_client = run_client(cont_dummy_client, ['-b', servers[0]+':8942'])

        # check if the dummy client is connected to server A
        if not tunneldigger.check_ping(cont_dummy_client, '192.168.254.1', 10):
            raise RuntimeError("Dummy Client failed to ping server")

        # -a = usage broker
        client_args = ['-a']
        for srv in servers:
            client_args.append('-b')
            client_args.append(srv + ":8942")
        pid_client = run_client(cont_client, client_args)

        # check if the client is connected to some server
        if not tunneldigger.check_ping(cont_client, '192.168.254.1', 10):
            raise RuntimeError("Test client failed to ping server")

        # now everything is connect. let's see if it's connecting to server B
        address = run_as_lxc(cont_client, ['curl', '--silent', 'http://192.168.254.1:8080/ip.txt']).decode()
        # FIXME: LXC has some strange bug where a `_after_at_fork_child_reinit_locks` error appears in all the output.
        # So `address` here will be that error followed by the address we want...
        if not address.endswith(servers[1]):
            raise RuntimeError('Client is connected to "%s" but should be "%s"' % (address, bytes(servers[1], 'utf-8')))
