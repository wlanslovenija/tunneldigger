#!/usr/bin/env python

import lxc
from random import randint
from subprocess import check_call, check_output
from time import sleep
import argparse
import os
import shlex
import signal
import sys
from threading import Timer

def LOG(msg):
    print("[TEST] {}".format(msg), flush=True)

def lxc_run_command(container, command):
    if container.attach_wait(lxc.attach_run_command, command):
        raise RuntimeError("failed to run command: {}", command)

def setup_template(ubuntu_release):
    """ all test container are cloned from this one
    it's important that this container is *NOT* running!
    """
    LOG("Creating base container (Ubuntu {})".format(ubuntu_release))
    container = lxc.Container("tunneldigger-base")

    if not container.defined:
        for i in range(0, 5): # retry a few times, this tends to fail spuriously on travis
            if i > 0:
                print("container creation failed, retrying after some waiting...")
                sleep(30) # wait a bit before next attempt
            if container.create("download", args={"dist": "ubuntu", "release": ubuntu_release, "arch": "amd64"}):
                break
        else:
            raise RuntimeError("failed to create container")

    if not container.running:
        if not container.start():
            raise RuntimeError("failed to start container")

    lxc_run_command(container, ["ip", "a"])
    lxc_run_command(container, ["dhclient", "eth0"])
    lxc_run_command(container, ["ip", "a"])
    lxc_run_command(container, ["apt-get", "update"])
    lxc_run_command(container, ["apt-get", "dist-upgrade", "-y"])

    # tunneldigger requirements
    # we install all requirements of past and present versions
    # so that we can run both older and newer versions of the code
    # with the same container setup
    pkg_to_install = [
        "iproute2",
        "bridge-utils",
        "libnetfilter-conntrack3",
        "python2-dev",
        "python3-dev",
        "libevent-dev",
        "ebtables",
        "virtualenv",
        "build-essential",
        "cmake",
        "libnl-3-dev",
        "libnl-genl-3-dev",
        "libasyncns-dev",
        "linux-libc-dev",
        "libffi-dev",
        "libnfnetlink-dev",
        "libnetfilter-conntrack-dev",
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

    lxc_run_command(container, ["apt-get", "install", "-y"] + pkg_to_install)
    container.shutdown(30)

def get_random_context():
    """ return a random hex similiar to mktemp, but do not check is already used """
    context = randint(0, 2**32)
    context = hex(context)[2:]
    return context

def configure_network(container, bridge, ip_netmask):
    """ configure the container and connect them to the bridge
    container is a lxc container
    bridge the name of your bridge to attach the container
    ip_netmask is the give address in cidr. e.g. 192.168.1.2/24"""
    config = [
        ('lxc.net.1.type', 'veth'),
        ('lxc.net.1.link', bridge),
        ('lxc.net.1.flags', 'up'),
        ('lxc.net.1.ipv4.address', ip_netmask),
    ]

    for item in config:
        container.append_config_item(item[0], item[1])

def configure_mounts(container):
    # mount testing dir
    local_path = os.path.dirname(os.path.realpath(__file__))
    git_repo = local_path + '/../.git'
    LOG("Git repo is at {}".format(git_repo))

    # TODO: this mount is very dirty and may be DANGEROUS!!! Unescaped.
    # mount this directory to /testing
    container.append_config_item('lxc.mount.entry', '%s testing none bind,ro,create=dir 0 0' % local_path)
    container.append_config_item('lxc.mount.entry', '%s git_repo none bind,ro,create=dir 0 0' % git_repo)

    # TODO: check if this is required because of libc-dev package
    container.append_config_item('lxc.mount.entry', '/usr/src usr/src none bind,ro 0 0')

def create_bridge(name):
    """ setup a linux bridge device """
    LOG("Creating bridge %s" % name)
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
    print(("generate a run for %s" % context))
    client, server = prepare_containers(context, client_rev, server_rev)
    spid = run_server(server)
    cpid = run_client(client, ['-b', '172.16.16.1:8942'])

    # wait until client is connected to server
    if not check_ping(client, '192.168.254.1', 20):
        raise RuntimeError('Tunneldigger client can not connect to the server')
    run_tests(server, client)

def prepare(cont_type, name, revision, bridge, ip_netmask='172.16.16.1/24'):
    if cont_type not in ['server', 'client']:
        raise RuntimeError('Unknown container type given')
    if lxc.Container(name).defined:
        raise RuntimeError('Container "%s" already exist!' % name)
    LOG("Preparing %s (type=%s, ip=%s, revision=%s)" % (name, cont_type, ip_netmask, revision))

    base = lxc.Container("tunneldigger-base")

    if not base.defined:
        raise RuntimeError("Setup first the base container")

    if base.running:
        raise RuntimeError(
            "base container %s is still running."
            "Please run lxc-stop --name %s -t 5" %
            (base.name, base.name))

    LOG("Cloning base (%s) to server (%s)" %(base.name, name))
    cont = base.clone(name, flags=lxc.LXC_CLONE_SNAPSHOT, bdevtype='overlayfs')
    if not cont:
        raise RuntimeError('could not create container "%s"' % name)
    configure_network(cont, bridge, ip_netmask)

    configure_mounts(cont)
    if not cont.start():
        raise RuntimeError("Can not start container %s" % cont.name)
    sleep(3)
    # ping does not work on GHA...
    #if not check_ping(cont, 'google-public-dns-a.google.com', 20):
    #    raise RuntimeError("Container doesn't have an internet connection %s"
    #            % cont.name)

    script = '/testing/prepare_%s.sh' % cont_type
    LOG("Server %s run %s" % (name, script))
    ret = cont.attach_wait(lxc.attach_run_command, [script, revision])
    if ret != 0:
        raise RuntimeError('Failed to prepare the container "%s" type %s' % (name, cont_type))
    LOG("Finished prepare_server %s" % name)
    return cont

def prepare_containers(context, client_rev, server_rev):
    """ this does the real test.
    - cloning containers from tunneldigger-base
    - setup network
    - checkout git repos
    - execute "compiler" steps
    - return clientcontainer, servercontainer
    """

    generate_test_file()

    server_name = "%s_server" % context
    client_name = "%s_client" % context
    bridge_name = "br-%s" % context

    create_bridge(bridge_name)
    server = prepare('server', server_name, server_rev, bridge_name, '172.16.16.1/24')
    client = prepare('client', client_name, client_rev, bridge_name, '172.16.16.100/24')

    return client, server

def run_server(server):
    """ run_server(server)
    server is a container
    """
    spid = server.attach(lxc.attach_run_command, ['/testing/run_server.sh'])
    return spid

def run_client(client, client_arguments):
    """ run_client(client)
    client is a container
    arguments must contains at least one server in the format ['-b', 'localhost:8942']
    """

    arguments = ['/testing/run_client.sh']
    arguments.extend(client_arguments)
    cpid = client.attach(lxc.attach_run_command, arguments)
    return cpid

def run_tests(server, client):
    """ the client should be already connect to the server """
    ret = client.attach_wait(lxc.attach_run_command, [
        "wget", "-t", "2", "-T", "4", "http://192.168.254.1:8080/testing/test-data/test_8m", '-O', '/dev/null'])
    if ret != 0:
        raise RuntimeError("failed to run the tests")

def clean_up(context, client, server):
    """ clean the up all bridge and containers created by this scripts. It will also abort all running tests."""
    LOG("ctx %s clean up" % context)
    # stop containers
    for cont in [client, server]:
        if cont.running:
            LOG("ctx %s hardstop container %s" % (context, cont.name))
            cont.shutdown(0)
        LOG("ctx %s destroy container %s" % (context, cont.name))
        cont.destroy()

    # remove bridge
    bridge_name = 'br-%s' % context
    if os.path.exists('/sys/devices/virtual/net/%s' % bridge_name):
        LOG("ctx %s destroy bridge %s" % (context, bridge_name))
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

def run_as_lxc(container, command, timeout=10):
    """
    run command within container and returns output

    command is a list of command and arguments,
    The output is limited to the buffersize of pipe (64k on linux)
    """
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    pid = container.attach(lxc.attach_run_command, command, stdout=write_fd, stderr=write_fd)
    timer = Timer(timeout, os.kill, args=(pid, signal.SIGKILL), kwargs=None)
    if timeout:
        timer.start()
    output_list = []
    os.waitpid(pid, 0)
    timer.cancel()
    try:
        while True:
            output_list.append(os.read(read_fd, 1024))
    except BlockingIOError:
        pass
    return bytes().join(output_list)

def check_if_git_contains(container, repo_path, top_commit, search_for_commit):
    """ checks if a git commit is included within a certain tree
    look into repo under *repo_path*, check if search_for_commit is included in the top_commit
    """
    cmd = ['sh', '-c', 'cd %s ; git merge-base "%s" "%s"' % (repo_path, top_commit, search_for_commit)]
    base = run_as_lxc(container, cmd)
    sys.stderr.write("\nGIT call is %s\n" % cmd)
    sys.stderr.write("\nGIT returns is %s\n" % base)
    if base.startswith(bytes(search_for_commit, 'utf-8')):
        # the base must be the search_for_commit when search_for_commit should included into top_commit
        # TODO: replace with git merge-base --is-ancestor
        return True
    return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Test Tunneldigger version against each other")
    # operation on the hosts
    parser.add_argument('--check-host', dest='check_host', action='store_true', default=False,
            help="Check if the host has all requirements installed")
    parser.add_argument('--setup', dest='setup', type=str,
            help="Setup the basic template for the given ubuntu release")
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
        setup_template(args.setup)

    if args.test:
        if not args.server or not args.client:
            raise RuntimeError("No client or server revision given. E.g. --test --server aba123 --client aba123.")
        testing(args.client, args.server)

    if args.clean:
        raise RuntimeError("not yet implemented...")
