#!/usr/bin/env python

import logging
import os
import tunneldigger
from tunneldigger import check_if_git_contains, run_server, run_client, run_as_lxc

# a revision which supports the usage command
USAGE_REV = 'a798e7c6621b6842246fc5696c6edb6a705fbad9'
# a very old revision which does not support usage
NONUSAGE_REV = 'bc998ee2b69c6a9350d95429640cb8a6a1f44c45'

LOG = logging.getLogger("test_usage")

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

        if not check_if_git_contains(cont_client, '/git_repo', os.environ['CLIENT_REV'], USAGE_REV):
            try:
                from nose import SkipTest
            except ImportError:
                LOG.error("Can not skip test, returning without any Exception!")
                return
            raise SkipTest("Client too old for this test.")

        servers = ['172.16.16.100', '172.16.16.101', '172.16.16.102']
        cont_first = tunneldigger.prepare('server', CONTEXT + '_first_server', os.environ['CLIENT_REV'], bridge_name, servers[0]+'/24')
        cont_second = tunneldigger.prepare('server', CONTEXT + '_second_server', USAGE_REV, bridge_name, servers[1]+'/24', "trusty")
        cont_nonusage = tunneldigger.prepare('server', CONTEXT + '_third_server', NONUSAGE_REV, bridge_name, servers[2]+'/24', "trusty")
        cont_all_servers = [cont_first, cont_second, cont_nonusage]

        cont_dummy_client = tunneldigger.prepare('client', CONTEXT + '_dummy_client', os.environ['CLIENT_REV'],
                                                 bridge_name, '172.16.16.1/24')
        cont_all_clients = [cont_dummy_client, cont_client]

        # start all servers
        pids_all_servers = [run_server(x) for x in cont_all_servers]
        pid_dummy_client = run_client(cont_dummy_client, ['-b', servers[0]+':8942'])

        LOG.info("Created servers %s", [x.name for x in cont_all_servers])
        LOG.info("Created clients %s", [x.name for x in cont_all_clients])

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
        address = run_as_lxc(cont_client, ['curl', '--silent', 'http://192.168.254.1:8080/ip.txt'])
        if address != bytes(servers[1], 'utf-8'):
            raise RuntimeError('Client is connected to "%s" but should be "%s"' % (address, bytes(servers[1], 'utf-8')))

