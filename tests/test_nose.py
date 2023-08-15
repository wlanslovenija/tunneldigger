#!/usr/bin/env python

import logging
import lxc
import os
import signal
from time import sleep
import tunneldigger
from tunneldigger import run_as_lxc

# random hash
CONTEXT = None

# lxc container
SERVER = None
CLIENT = None

# pids of tunneldigger client and server
SERVER_PID = None
CLIENT_PID = None

LOG = logging.getLogger("test_nose")
DEFAULT_UBUNTU = "bionic"

def setup_module():
    global CONTEXT, SERVER, CLIENT, SERVER_PID, CLIENT_PID
    CONTEXT = tunneldigger.get_random_context()
    LOG.info("using context %s", CONTEXT)
    CLIENT, SERVER = tunneldigger.prepare_containers(CONTEXT,
                            os.environ['CLIENT_REV'], DEFAULT_UBUNTU,
                            os.environ['SERVER_REV'], os.environ.get('SERVER_UBUNTU', DEFAULT_UBUNTU))
    SERVER_PID = tunneldigger.run_server(SERVER)
    CLIENT_PID = tunneldigger.run_client(CLIENT, ['-b', '172.16.16.1:8942'])

    if not tunneldigger.check_ping(CLIENT, '172.16.16.1', 10):
        raise RuntimeError("Unable to ping server container, possible test network issue")

    # explicit no Exception when ping fails
    # it's better to poll the client for a ping rather doing a long sleep
    tunneldigger.check_ping(CLIENT, '192.168.254.1', 20)

def teardown_module():
    tunneldigger.clean_up(CONTEXT, CLIENT, SERVER)

class TestTunneldigger(object):
    def test_ping_tunneldigger_server(self):
        """ even we check earlier if the ping is working, we want to fail the check here.
        If we fail in setup_module, nose will return UNKNOWN state, because the setup fails and
        not a "test" """
        if not tunneldigger.check_ping(CLIENT, '192.168.254.1', 3):
            raise RuntimeError("fail to ping server")

    def test_wget_tunneldigger_server(self):
        ret = CLIENT.attach_wait(lxc.attach_run_command, [
            "wget", "-t", "2", "-T", "4", "http://192.168.254.1:8080/testing/test-data/test_8m", '-O', '/dev/null'])
        if ret != 0:
            raise RuntimeError("failed to run the tests")

    def test_ensure_tunnel_up_for_1m(self):
        # get id of l2tp0 iface
        first_interface_id = run_as_lxc(CLIENT, ['bash', '-c', 'ip -o link show l2tp0 | awk -F: \'{ print $1 }\''])
        # sleep 1 minute
        sleep(60)
        # get id of l2tp0 iface
        second_interface_id = run_as_lxc(CLIENT, ['bash', '-c', 'ip -o link show l2tp0 | awk -F: \'{ print $1 }\''])
        LOG.info("Check l2tp is stable for 1m. first id %s == %s second id " % (first_interface_id, second_interface_id))
        assert first_interface_id == second_interface_id
