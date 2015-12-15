#!/usr/bin/env python3

import lxc
from random import randint
from subprocess import check_call, check_output
from time import sleep
import argparse
import logging
import os
import shlex
import sys

GIT_URL = "https://github.com/wlanslovenija/tunneldigger"

LOG = logging.getLogger("test.tunneldigger")

def setup_template():
    """ all test container are cloned from this one
    it's important that this container is *NOT* running!
    """
    container = lxc.Container("tunneldigger-base")

    if not container.defined:
        if not container.create("download", lxc.LXC_CREATE_QUIET, {"dist": "ubuntu",
                                                                   "release": "trusty",
                                                                   "arch": "amd64"}):
            raise RuntimeError("failed to create container")

    if not container.running:
        if not container.start():
            raise RuntimeError("failed to start container")

    container.attach_wait(lxc.attach_run_command, ["dhclient", "eth0"])
    check_ping(container, '8.8.8.8', 10)
    container.attach_wait(lxc.attach_run_command, ["apt-get", "update"])
    container.attach_wait(lxc.attach_run_command, ["apt-get", "dist-upgrade", "-y"])

    # tunneldigger requirements
    pkg_to_install = [
        "iproute",
        "bridge-utils",
        "libnetfilter-conntrack3",
        "python-dev",
        "libevent-dev",
        "ebtables",
        "python-virtualenv",
        "build-essential",
        "libnl-dev",
        "linux-libc-dev",
        ]
    pkg_to_install += [
        "wget",
        "curl",
        "git",
        "iputils-ping"
        ]
    # for testing the connection
    pkg_to_install += [
        "lighttpd"
        ]

    container.attach_wait(lxc.attach_run_command, ["apt-get", "install", "-y"] + pkg_to_install)
    container.shutdown(30)

def get_random_context():
    """ return a random hex similiar to mktemp, but do not check is already used """
    context = randint(0, 2**32)
    context = hex(context)[2:]
    return context

def configure_network(container, bridge, is_server):
    """ configure the container and connect them to the bridge 
    container is a lxc container
    context is the hex for the bridge """
    config = [
        ('lxc.network.type', 'veth'),
        ('lxc.network.link', bridge),
        ('lxc.network.flags', 'up'),
        ]
    if is_server:
        config.append(
            ('lxc.network.ipv4', '172.16.16.1/24'),
            )
    else:
        config.append(
            ('lxc.network.ipv4', '172.16.16.2/24'),
            )

    for item in config:
        container.append_config_item(item[0], item[1])

def configure_mounts(container):
    # mount testing dir
    local_path = os.path.dirname(os.path.realpath(__file__))
    git_repo = local_path + '/../.git'

    # TODO: this mount is very dirty and may be DANGEROUS!!! Unescaped.
    # mount this directory to /testing
    container.append_config_item('lxc.mount.entry', '%s testing none bind,ro,create=dir 0 0' % local_path)
    container.append_config_item('lxc.mount.entry', '%s git_repo none bind,ro,create=dir 0 0' % git_repo)

    # TODO: check if this is required because of libc-dev package
    container.append_config_item('lxc.mount.entry', '/usr/src usr/src none bind,ro 0 0')

def create_bridge(name):
    """ setup a linux bridge device """
    LOG.info("Creating bridg %s", name)
    check_call(["brctl", "addbr", name], timeout=10)
    check_call(["ip", "link", "set", name, "up"], timeout=10)

    # FIXME: lxc_container: confile.c: network_netdev: 474 no network device defined for 'lxc.network.1.link' = 'br-46723922' option
    sleep(3)

def check_ping(container, server, tries):
    """ check the internet connectivity inside the container """
    ping = 'ping -c 1 -W 1 %s' % server
    for i in range(0, tries):
        ret = container.attach_wait(lxc.attach_run_command, shlex.split(ping))
        if ret == 0:
            return True
        sleep(1)
    return False

def generate_test_file():
    """ generate a test file with sha256sum"""
    local_path = os.path.dirname(os.path.realpath(__file__))
    test_data = local_path + '/test-data'
    test_8m = test_data + '/test_8m'
    sum_file = test_data + '/sha256sum'
    if not os.path.exists(test_data):
        os.mkdir(test_data)
    if not os.path.exists(test_8m):
        check_call(['dd', 'if=/dev/urandom', 'of=%s' % test_8m, 'bs=1M', 'count=8'])
        output = check_output(['sha256sum', test_8m], cwd=test_data)
        f = open(sum_file, 'wb')
        f.write(output)
        f.close()

def testing(client_rev, server_rev):
    context = get_random_context()
    print("generate a run for %s" % context)
    client, server = prepare_containers(context, client_rev, server_rev)
    spid = run_server(server)
    cpid = run_client(client)

    # wait until client is connected to server
    if not check_ping(client, '192.168.254.1', 20):
        raise RuntimeError('Tunneldigger client can not connect to the server')
    run_tests(server, client)

def prepare_containers(context, client_rev, server_rev):
    """ this does the real test.
    - cloning containers from tunneldigger-base
    - setup network
    - checkout git repos
    - execute "compiler" steps
    - return clientcontainer, servercontainer
    """
    base = lxc.Container("tunneldigger-base")
    if not base.defined:
        raise RuntimeError("Setup first the base container")

    generate_test_file()

    server_name = "%s_server" % context
    client_name = "%s_client" % context
    bridge_name = "br-%s" % context
    server = lxc.Container(server_name)
    client = lxc.Container(client_name)

    if base.running:
        raise RuntimeError("base container %s is still running. Please run lxc-stop --name %s -t 5" % (base.name, base.name))

    if server.defined or client.defined:
        raise RuntimeError("server or client container already exist")

    create_bridge(bridge_name)

    LOG.info("ctx %s cloning containers", context)
    server = base.clone(server_name, None, lxc.LXC_CLONE_SNAPSHOT, bdevtype='aufs')
    client = base.clone(client_name, None, lxc.LXC_CLONE_SNAPSHOT, bdevtype='aufs')

    if not server:
        if client:
            client.destroy()
        raise RuntimeError("could not create server container %s" % server_name)
    if not client:
        if server:
            server.destroy()
        raise RuntimeError("could not create client container %s" % client_name)

    configure_network(server, bridge_name, True)
    configure_network(client, bridge_name, False)

    for cont in [client, server]:
        configure_mounts(cont)
        if not cont.start():
          raise RuntimeError("Can not start container %s" % cont.name)
        sleep(3)
        if not check_ping(cont, '8.8.8.8', 20):
            raise RuntimeError("Container doesn't have an internet connection %s" % cont.name)

    LOG.info("ctx %s prepare server", context)
    ret = server.attach_wait(lxc.attach_run_command, ['/testing/prepare_server.sh', server_rev])
    if ret != 0:
        raise RuntimeError("Failed to prepare the server")
    LOG.info("ctx %s finished prepare server", context)

    LOG.info("ctx %s prepare client", context)
    ret = client.attach_wait(lxc.attach_run_command, ['/testing/prepare_client.sh', client_rev])
    if ret != 0:
        raise RuntimeError("Failed to prepare the server")
    LOG.info("ctx %s finished prepare client", context)
    return client, server

def run_server(server):
    """ run_server(server)
    server is a container
    """
    spid = server.attach(lxc.attach_run_command, ['/testing/run_server.sh'])
    return spid

def run_client(client):
    """ run_client(client)
    client is a container
    """
    cpid = client.attach(lxc.attach_run_command, ['/testing/run_client.sh'])
    return cpid

def run_tests(server, client):
    """ the client should be already connect to the server """
    ret = client.attach_wait(lxc.attach_run_command, ["wget", "-t", "2", "-T", "4", "http://192.168.254.1:8080/test_8m", '-O', '/dev/null'])
    if ret != 0:
        raise RuntimeError("failed to run the tests")

def clean_up(context, client, server):
    """ clean the up all bridge and containers created by this scripts. It will also abort all running tests."""
    LOG.info("ctx %s clean up", context)
    # stop containers
    for cont in [client, server]:
        if cont.running:
            LOG.debug("ctx %s hardstop container %s", context, cont.name)
            cont.shutdown(0)
        LOG.debug("ctx %s destroy container %s", context, cont.name)
        cont.destroy()

    # remove bridge
    bridge_name = 'br-%s' % context
    if os.path.exists('/sys/devices/virtual/net/%s' % bridge_name):
        LOG.info("ctx %s destroy bridge %s", context, bridge_name)
        check_call(["ip", "link", "set", bridge_name, "down"], timeout=10)
        check_call(["brctl", "delbr", bridge_name], timeout=10)

def check_host():
    """ check if the host has all known requirements to run this script """
    have_brctl = False

    try:
        check_call(["brctl", "--version"], timeout=3)
        have_brctl = True
    except Exception:
        pass

    if not have_brctl:
        sys.stderr.write("No brctl installed\n")

    if have_brctl:
        print("Everything is installed")
        return True
    raise RuntimeError("Missing dependencies. See stderr for more info")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Test Tunneldigger version against each other")
    # operation on the hosts
    parser.add_argument('--check-host', dest='check_host', action='store_true', default=False,
            help="Check if the host has all requirements installed")
    parser.add_argument('--setup', dest='setup', action='store_true', default=False,
            help="Setup the basic template. Must run once before doing the tests.")
    # testing arguments
    parser.add_argument('-t', '--test', dest='test', action='store_true', default=False,
            help="Do a test run. Server rev and Client rev required. See -s and -c.")
    parser.add_argument('-s', '--server', dest='server', type=str,
            help="The revision used by the server")
    parser.add_argument('-c', '--client', dest='client', type=str,
            help="The revision used by the client")
    # clean up
    parser.add_argument('--clean', action='store_true', default=False,
            help="Clean up (old) containers and bridges. This will kill all running tests!")

    args = parser.parse_args()

    if not args.check_host and not args.setup and not args.test and not args.clean:
      parser.print_help()

    if args.check_host:
        check_host()

    if args.setup:
        setup_template()

    if args.test:
        if not args.server or not args.client:
            raise RuntimeError("No client or server revision given. E.g. --test --server aba123 --client aba123.")
        testing(args.client, args.server)

    if args.clean:
        clean_up()
