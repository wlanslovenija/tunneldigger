#!/usr/bin/python
#
# Broker for our custom L2TPv3 brokerage protocol.
#
# Copyright (C) 2012 by Jernej Kos <k@jst.sm>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
import ConfigParser
import conntrack
import construct as cs
import datetime
import gevent
import gevent.socket as gsocket
import gevent_subprocess
import genetlink
import logging
import netfilter.rule
import netfilter.table
import netlink
import os
import repoze.lru
import signal
import sys
import traceback

# Control message for our protocol; first few bits are special as we have to
# maintain compatibility with LTPv3 in the kernel (first bit must be 1); also
# the packet must be at least 12 bytes in length, otherwise some firewalls
# may filter it when used over port 53
ControlMessage = cs.Struct("control",
  # Ensure that the first bit is 1 (L2TP control packet)
  cs.Const(cs.UBInt8("magic1"), 0x80),
  # Reduce conflict matching to other protocols as we run on port 53
  cs.Const(cs.UBInt16("magic2"), 0x73A7),
  # Protocol version to allow future upgrades
  cs.UBInt8("version"),
  # Message type
  cs.UBInt8("type"),
  # Message data (with length prefix)
  cs.PascalString("data"),
  # Pad the message so it is at least 12 bytes long
  cs.Padding(lambda ctx: max(0, 6 - len(ctx["data"]))),
)

CONTROL_TYPE_COOKIE    = 0x01
CONTROL_TYPE_PREPARE   = 0x02
CONTROL_TYPE_ERROR     = 0x03
CONTROL_TYPE_TUNNEL    = 0x04
CONTROL_TYPE_KEEPALIVE = 0x05

# Prepare message
PrepareMessage = cs.Struct("prepare",
  cs.String("cookie", 8),
  cs.PascalString("uuid"),
  cs.Optional(cs.UBInt16("tunnel_id")),
)

# L2TP generic netlink
L2TP_GENL_NAME = "l2tp"
L2TP_GENL_VERSION = 0x1

# L2TP netlink commands
L2TP_CMD_TUNNEL_CREATE = 1
L2TP_CMD_TUNNEL_DELETE = 2
L2TP_CMD_TUNNEL_GET = 4
L2TP_CMD_SESSION_CREATE = 5
L2TP_CMD_SESSION_DELETE = 6
L2TP_CMD_SESSION_GET = 8

# L2TP netlink command attributes
L2TP_ATTR_NONE = 0
L2TP_ATTR_PW_TYPE = 1
L2TP_ATTR_ENCAP_TYPE = 2
L2TP_ATTR_PROTO_VERSION = 7
L2TP_ATTR_IFNAME = 8
L2TP_ATTR_CONN_ID = 9
L2TP_ATTR_PEER_CONN_ID = 10
L2TP_ATTR_SESSION_ID = 11
L2TP_ATTR_PEER_SESSION_ID = 12
L2TP_ATTR_FD = 23

# L2TP encapsulation types
L2TP_ENCAPTYPE_UDP = 0

# L2TP pseudowire types
L2TP_PWTYPE_ETH = 0x0005

# Logger
logger = None

class NetlinkError(Exception):
  pass

class L2TPSupportUnavailable(NetlinkError):
  pass

class L2TPTunnelExists(NetlinkError):
  pass

class NetlinkInterface(object):
  """
  NETLINK interface to L2TP kernel module.
  """
  def __init__(self):
    """
    Class constructor.
    """
    # Establish a connection to the kernel via the NETLINK socket
    self.connection = netlink.Connection(netlink.NETLINK_GENERIC)
    controller = genetlink.Controller(self.connection)
    try:
      self.family_id = controller.get_family_id(L2TP_GENL_NAME)
    except OSError:
      raise L2TPSupportUnavailable
  
  def _create_message(self, command, attributes, flags = netlink.NLM_F_REQUEST | netlink.NLM_F_ACK): 
    return genetlink.GeNlMessage(self.family_id, cmd = command, version = L2TP_GENL_VERSION,
      attrs = attributes, flags = flags)
  
  def tunnel_create(self, tunnel_id, peer_tunnel_id, socket):
    """
    Creates a new L2TP tunnel.
    
    :param tunnel_id: Local tunnel identifier
    :param peer_tunnel_id: Remote peer tunnel identifier
    :param socket: UDP socket file descriptor
    """
    msg = self._create_message(L2TP_CMD_TUNNEL_CREATE, [
      netlink.U32Attr(L2TP_ATTR_CONN_ID, tunnel_id),
      netlink.U32Attr(L2TP_ATTR_PEER_CONN_ID, peer_tunnel_id),
      netlink.U8Attr(L2TP_ATTR_PROTO_VERSION, 3),
      netlink.U16Attr(L2TP_ATTR_ENCAP_TYPE, L2TP_ENCAPTYPE_UDP),
      netlink.U32Attr(L2TP_ATTR_FD, socket),
    ])
    msg.send(self.connection)
    
    try:
      reply = self.connection.recv()
    except OSError, e:
      if e.errno == 17:
        # This tunnel identifier is already in use; make sure to remove it from
        # our pool of assignable tunnel identifiers
        raise L2TPTunnelExists
      
      raise NetlinkError
  
  def tunnel_delete(self, tunnel_id):
    """
    Deletes an existing tunnel.
    
    :param tunnel_id: Local tunnel identifier
    """
    msg = self._create_message(L2TP_CMD_TUNNEL_DELETE, [
      netlink.U32Attr(L2TP_ATTR_CONN_ID, tunnel_id),
    ])
    msg.send(self.connection)
    
    try:
      reply = self.connection.recv()
    except OSError:
      logger.debug(traceback.format_exc())
      logger.warning("Unable to remove tunnel %d!" % tunnel_id)
  
  def tunnel_list(self):
    """
    Returns a list of tunnel identifiers.
    """
    tunnels = []
    msg = self._create_message(L2TP_CMD_TUNNEL_GET, [],
      flags = netlink.NLM_F_REQUEST | netlink.NLM_F_DUMP | netlink.NLM_F_ACK)
    msg.send(self.connection)
    
    for tunnel in genetlink.GeNlMessage.recv(self.connection, multiple = True):
      tunnels.append(session.attrs[L2TP_ATTR_CONN_ID].u32()) 
    
    return tunnels
  
  def session_create(self, tunnel_id, session_id, peer_session_id, name):
    """
    Creates a new ethernet session over the tunnel.
    
    :param tunnel_id: Local tunnel identifier
    :param session_id: Local session identifier
    :param peer_session_id: Remote peer session identifier
    :param name: Interface name
    """
    msg = self._create_message(L2TP_CMD_SESSION_CREATE, [
      netlink.U32Attr(L2TP_ATTR_CONN_ID, tunnel_id),
      netlink.U32Attr(L2TP_ATTR_SESSION_ID, session_id),
      netlink.U32Attr(L2TP_ATTR_PEER_SESSION_ID, peer_session_id),
      netlink.U16Attr(L2TP_ATTR_PW_TYPE, L2TP_PWTYPE_ETH),
      # TODO cookies
      netlink.NulStrAttr(L2TP_ATTR_IFNAME, name),
    ])
    msg.send(self.connection)
    
    try:
      reply = self.connection.recv()
    except OSError, e:
      raise NetlinkError
  
  def session_delete(self, tunnel_id, session_id):
    """
    Deletes an existing session.
    
    :param tunnel_id: Local tunnel identifier
    :param session_id: Local session identifier
    """
    msg = self._create_message(L2TP_CMD_SESSION_DELETE, [
      netlink.U32Attr(L2TP_ATTR_CONN_ID, tunnel_id),
      netlink.U32Attr(L2TP_ATTR_SESSION_ID, session_id),
    ])
    msg.send(self.connection)
    
    try:
      reply = self.connection.recv()
    except OSError:
      logger.debug(traceback.format_exc())
      logger.warning("Unable to remove tunnel %d session %d!" % (tunnel_id, session_id))
  
  def session_list(self):
    """
    Returns a list of session identifiers for each tunnel.
    """
    sessions = []
    msg = self._create_message(L2TP_CMD_SESSION_GET, [],
      flags = netlink.NLM_F_REQUEST | netlink.NLM_F_DUMP | netlink.NLM_F_ACK)
    msg.send(self.connection)
    
    for session in genetlink.GeNlMessage.recv(self.connection, multiple = True):
      sessions.append(
        (session.attrs[L2TP_ATTR_CONN_ID].u32(), session.attrs[L2TP_ATTR_SESSION_ID].u32())
      ) 
    
    return sessions

class Session(object):
  id = None
  peer_id = None
  name = None

class TunnelSetupFailed(Exception):
  pass

class Tunnel(gevent.Greenlet):
  def __init__(self, manager):
    """
    Class constructor.
    
    :param manager: An instance of TunnelManager
    """
    super(Tunnel, self).__init__()
    self.manager = manager
    self.handler = MessageHandler(manager, self)
    self.sessions = {}
    self.next_session_id = 1
    self.keep_alive()
    
  def setup(self):
    """
    Setup the tunnel and netfilter rules.
    """
    self.setup_tunnel()
    try:
      self.setup_netfilter()
    except TunnelSetupFailed:
      # Ensure that the tunnel gets closed in case netfilter code fails
      # to execute - so we don't get lingering tunnels
      self.socket.close()
      raise
    
    # Spawn periodic keepalive transmitter
    self.keep_alive_do = gevent.spawn(self._keep_alive_do)
  
  def _keep_alive_do(self):
    """
    Periodically transmits keepalives over the tunnel and checks
    if the tunnel has timed out due to inactivity.
    """
    while True:
      try:
        self.handler.send_message(self.socket, CONTROL_TYPE_KEEPALIVE)
      except gsocket.error:
        pass
      
      # Check if we are still alive or not; if not, kill the tunnel
      timeout_interval = self.manager.config.getint("tunnel_timeout")
      if datetime.datetime.now() - self.last_alive > datetime.timedelta(seconds = timeout_interval):
        logger.warning("Session with tunnel %d to %s:%d timed out." % (self.id, self.endpoint[0],
          self.endpoint[1]))
        gevent.spawn(self.manager.close_tunnel, self)
        return
      
      gevent.sleep(5.0)
  
  def _run(self):
    """
    Starts listening for control messages via the tunnel socket.
    """
    while True:
      # Receive control messages from the socket
      try:
        data, address = self.socket.recvfrom(1024)
      except gsocket.error, e:
        if e.errno != 9:
          logger.error("Socket error %d in tunnel %d with %s:%d!" % (e.errno, 
            self.id, self.endpoint[0], self.endpoint[1]))
        else:
          logger.warning("Closing control channel for tunnel %d." % self.id)
        
        return
      
      if address != self.endpoint:
        # Ignore messages from unknown sources
        continue
      
      # All packets count as liveness indicators
      self.keep_alive()
      
      msg = self.handler.handle(self.socket, data, address)
      if msg is None:
        # Message has been handled or is invalid
        continue
      elif msg.type == CONTROL_TYPE_ERROR:
        logger.warning("Error message received from client, tearing down tunnel %d." % self.id)
        gevent.spawn(self.manager.close_tunnel, self)
        return
  
  def close(self, kill = True):
    """
    Close the tunnel and remove all mappings.
    """
    self.keep_alive_do.kill()
    
    for session in self.sessions.values():
      # Invoke any pre-down hooks
      self.manager.hook('session.pre-down', self.id, session.id, session.name, self.endpoint[0],
        self.endpoint[1], self.port)
      
      self.manager.netlink.session_delete(self.id, session.id)
      
      # Invoke any down hooks
      self.manager.hook('session.down', self.id, session.id, session.name, self.endpoint[0],
        self.endpoint[1], self.port)
    
    # Transmit error message so the other end can tear down the tunnel
    # immediately instead of waiting for keepalive timeout
    try:
      self.handler.send_message(self.socket, CONTROL_TYPE_ERROR)
    except gsocket.error:
      pass
    
    self.socket.close()
    self.remove_netfilter()
    
    if kill:
      self.kill()
  
  def setup_tunnel(self):
    """
    Sets up the L2TPv3 kernel tunnel for data transfer.
    """
    try:
      self.socket = gsocket.socket(gsocket.AF_INET, gsocket.SOCK_DGRAM)
      self.socket.bind((self.manager.address, self.port))
      self.socket.connect(self.endpoint)
    except gsocket.error:
      raise TunnelSetupFailed
    
    # Make the socket an encapsulation socket by asking the kernel to do so
    try:
      self.manager.netlink.tunnel_create(self.id, self.peer_id, self.socket.fileno())
      session = self.create_session()
    except L2TPTunnelExists:
      self.socket.close()
      raise
    except NetlinkError:
      self.socket.close()
      raise TunnelSetupFailed
  
  def call_session_up_hooks(self):
    """
    Invokes any registered session establishment hooks for all sessions. This
    method must be called AFTER the tunnel has been established (after a
    confirmation packet has been transmitted from the broker to the client),
    otherwise port translation will not work and the tunnel will be dead.
    """
    for session in self.sessions.values():
      self.manager.hook('session.up', self.id, session.id, session.name, self.endpoint[0],
        self.endpoint[1], self.port)
  
  def create_session(self):
    """
    Creates a new session over this tunnel.
    """
    session = Session()
    session.id = self.next_session_id
    session.peer_id = session.id
    session.name = "l2tp%d%d" % (self.id, session.id) 
    self.sessions[session.id] = session
    self.next_session_id += 1
    
    try:
      self.manager.netlink.session_create(self.id, session.id, session.peer_id,
        session.name)
    except:
      del self.sessions[session.id]
      raise
    
    return session
  
  def setup_netfilter(self):
    """
    Sets up the netfilter rules for port translation.
    """
    self.prerouting_rule = netfilter.rule.Rule(
      in_interface = self.manager.interface,
      protocol = 'udp',
      source = self.endpoint[0],
      destination = self.manager.address,
      matches = [
        netfilter.rule.Match('udp', '--sport %d --dport %d' % (self.endpoint[1], self.manager.port)),
      ],
      jump = netfilter.rule.Target('DNAT', '--to %s:%d' % (self.manager.address, self.port))
    )
    
    self.postrouting_rule = netfilter.rule.Rule(
      out_interface = self.manager.interface,
      protocol = 'udp',
      source = self.manager.address,
      destination = self.endpoint[0],
      matches = [
        netfilter.rule.Match('udp', '--sport %d --dport %d' % (self.port, self.endpoint[1])),
      ],
      jump = netfilter.rule.Target('SNAT', '--to %s:%d' % (self.manager.address, self.manager.port))
    )
    
    try:
      nat = netfilter.table.Table('nat')
      nat.append_rule('L2TP_PREROUTING', self.prerouting_rule)
      nat.append_rule('L2TP_POSTROUTING', self.postrouting_rule)
    except netfilter.table.IptablesError:
      raise TunnelSetupFailed

  def clear_conntrack(self):
    """
    Removes existing conntrack mappings, forcing the kernel to re-evaluate
    netfilter rules.
    """
    try:
      self.manager.conntrack.kill(conntrack.IPPROTO_UDP, self.endpoint[0], self.manager.address,
        self.endpoint[1], self.manager.port)
      self.manager.conntrack.kill(conntrack.IPPROTO_UDP, self.manager.address, self.endpoint[0],
        self.manager.port, self.endpoint[1])
    except conntrack.ConntrackError:
      pass

  def remove_netfilter(self):
    """
    Remove the netfilter rules for port translation.
    """
    try:
      nat = netfilter.table.Table('nat')
      nat.delete_rule('L2TP_PREROUTING', self.prerouting_rule)
      nat.delete_rule('L2TP_POSTROUTING', self.postrouting_rule)
    except netfilter.table.IptablesError:
      pass
  
  def keep_alive(self):
    """
    Marks this tunnel as alive at this moment.
    """
    self.last_alive = datetime.datetime.now()

class TunnelManager(object):
  def __init__(self, config):
    """
    Class constructor.
    
    :param config: The configuration object
    """
    logger.info("Setting up the tunnel manager...")
    self.config = config
    max_tunnels = config.getint('broker', 'max_tunnels')
    self.netlink = NetlinkInterface()
    self.conntrack = conntrack.ConnectionManager()
    self.tunnels = {}
    self.cookies = repoze.lru.LRUCache(config.getint('broker', 'max_cookies'))
    self.secret = os.urandom(32)
    id_base = config.getint('broker', 'tunnel_id_base')
    self.tunnel_ids = range(id_base, id_base + max_tunnels + 1)
    self.port_base = config.getint('broker', 'port_base')
    self.interface = config.get('broker', 'interface')
    self.address = config.get('broker', 'address')
    self.port = config.getint('broker', 'port')
    self.setup_tunnels()
    self.setup_netfilter()
    self.setup_hooks()
    
    # Log some configuration variables
    logger.info("  Maximum number of tunnels: %d" % max_tunnels)
    logger.info("  Interface: %s" % self.interface)
    logger.info("  Address: %s" % self.address)
    logger.info("  Port: %d" % self.port)
    logger.info("Tunnel manager initialized.")
  
  def setup_hooks(self):
    """
    Sets up any registered hooks.
    """
    self.hooks = {}
    for hook, script in self.config.items('hooks'):
      self.hooks[hook] = script
  
  def hook(self, name, *args):
    """
    Executes a given hook. All additional arguments are passed to the
    hook as script arguments.
    
    :param name: Hook name (like session.pre-up)
    """
    script = self.hooks.get(name, None)
    if not script:
      return
    
    # Execute the registered hook
    logger.debug("Executing hook '%s' via script '%s'..." % (name, script))
    gevent_subprocess.call([script] + [str(x) for x in args])
  
  def setup_tunnels(self):
    """
    Cleans up any stale tunnels that exist.
    """
    for tunnel_id, session_id in self.netlink.session_list():
      logger.warning("Removing existing tunnel %d session %d." % (tunnel_id, session_id))
      self.netlink.session_delete(tunnel_id, session_id)
    
    for tunnel_id in self.netlink.tunnel_list():
      logger.warning("Removing existing tunnel %d." % tunnel_id)
      self.netlink.tunnel_delete(tunnel_id)
  
  def setup_netfilter(self):
    """
    Sets up netfilter rules so new packets to the same port are redirected
    into the per-tunnel socket.
    """
    nat = netfilter.table.Table('nat')
    self.rule_prerouting_jmp = netfilter.rule.Rule(jump = 'L2TP_PREROUTING')
    self.rule_postrouting_jmp = netfilter.rule.Rule(jump = 'L2TP_POSTROUTING')
    
    try:
      nat.flush_chain('L2TP_PREROUTING')
      nat.delete_chain('L2TP_PREROUTING')
    except netfilter.table.IptablesError:
      pass
    
    try:
      nat.flush_chain('L2TP_POSTROUTING')
      nat.delete_chain('L2TP_POSTROUTING')
    except netfilter.table.IptablesError:
      pass
    
    nat.create_chain('L2TP_PREROUTING')
    nat.create_chain('L2TP_POSTROUTING')
    try:
      nat.delete_rule('PREROUTING', self.rule_prerouting_jmp)
    except netfilter.table.IptablesError:
      pass
    nat.append_rule('PREROUTING', self.rule_prerouting_jmp)
    
    try:
      nat.delete_rule('POSTROUTING', self.rule_postrouting_jmp)
    except netfilter.table.IptablesError:
      pass
    nat.append_rule('POSTROUTING', self.rule_postrouting_jmp)
    
    # Clear out the connection tracking tables
    self.conntrack.killall(proto = conntrack.IPPROTO_UDP, src = self.address)
    self.conntrack.killall(proto = conntrack.IPPROTO_UDP, dst = self.address)
  
  def restore_netfilter(self):
    """
    Removes previously setup netfilter rules.
    """
    nat = netfilter.table.Table('nat')
    nat.delete_rule('PREROUTING', self.rule_prerouting_jmp)
    nat.delete_rule('POSTROUTING', self.rule_postrouting_jmp)
    nat.delete_chain('L2TP_PREROUTING')
    nat.delete_chain('L2TP_POSTROUTING')
  
  def close(self):
    """
    Closes all tunnels and performs the necessary cleanup.
    """
    logger.info("Closing the tunnel manager...")
    
    # Ensure that all tunnels get closed
    for tunnel in self.tunnels.values():
      try:
        # Kill must not be called as the manager's close method can be called
        # from a signal handler and this may cause the greenlets to switch
        # to hub which may cause the application to exit prematurely
        tunnel.close(kill = False)
      except:
        logger.warning("Failed to close tunnel!")
        logger.debug(traceback.format_exc())
        continue
    
    self.restore_netfilter()
  
  def issue_cookie(self, endpoint):
    """
    Issues a new cookie for the given endpoint.
    
    :param endpoint: Endpoint tuple
    :return: Some random cookie data (8 bytes)
    """
    cookie = self.cookies.get(endpoint)
    if cookie is not None:
      return cookie
    
    cookie = os.urandom(8)
    self.cookies.put(endpoint, cookie)
    return cookie
  
  def verify_cookie(self, endpoint, cookie):
    """
    Verifies if the endpoint has generated a valid cookie.
    
    :param endpoint: Cookie
    """
    vcookie = self.cookies.get(endpoint)
    if not vcookie:
      return False
    
    return vcookie == cookie
  
  def close_tunnel(self, tunnel):
    """
    Closes an existing tunnel.
    
    :param Tunnel tunnel: A tunnel instance that should be closed
    """
    if tunnel.endpoint not in self.tunnels:
      return
    
    logger.info("Closing tunnel %d to %s:%d." % (tunnel.id, tunnel.endpoint[0],
      tunnel.endpoint[1]))
    
    try:
      tunnel.close()
    except:
      logger.error("Exception while closing tunnel %d to %s:%d!" % (tunnel.id,
        tunnel.endpoint[0], tunnel.endpoint[1]))
      logger.debug(traceback.format_exc())
    
    del self.tunnels[tunnel.endpoint]
    self.tunnel_ids.append(tunnel.id)
  
  def setup_tunnel(self, endpoint, uuid, cookie, tunnel_id):
    """
    Sets up a new tunnel or returns the data for an existing
    tunnel.
    
    :param endpoint: Tuple (ip, port) representing the endpoint
    :param uuid: Endpoint's UUID
    :param cookie: A random cookie used for this tunnel
    :param tunnel_id: Peer tunnel identifier
    
    :return: A tuple (tunnel, created) where tunnel is a Tunnel
      descriptor and created is a boolean flag indicating if a new
      tunnel has just been created; (None, False) if something went
      wrong
    """
    if endpoint in self.tunnels:
      tunnel = self.tunnels[endpoint]
      
      # Check if UUID is a match and abort if it isn't; we should
      # not overwrite endpoints
      if tunnel.uuid != uuid:
        return None, False
      
      # Check if peer tunnel id is a match and abort if it isn't
      if tunnel.peer_id != tunnel_id:
        return None, False
      
      # Update tunnel's liveness
      tunnel.keep_alive()
      return tunnel, False
    
    # Tunnel has not yet been created, create a new tunnel
    try:
      tunnel = Tunnel(self)
      tunnel.uuid = uuid
      tunnel.id = self.tunnel_ids.pop(0)
      tunnel.peer_id = tunnel_id
      tunnel.endpoint = endpoint
      tunnel.port = self.port_base + tunnel.id
      tunnel.cookie = cookie
      tunnel.setup()
    except IndexError:
      # No available tunnel indices, reject tunnel creation
      return None, False
    except L2TPTunnelExists:
      # Failed to setup a tunnel because the identifier already exists; abort,
      # but do not put the identifier back as tunnel with this identifier is
      # clearly not managed by us
      logger.warning("Tunnel with id %d already exists!" % tunnel.id)
      return None, False
    except TunnelSetupFailed:
      # Failed to setup a tunnel, abort now and reclaim the assigned id
      logger.error("Failed to setup tunnel with id %d!" % tunnel.id)
      self.tunnel_ids.append(tunnel.id)
      return None, False
    
    logger.info("New tunnel (id=%d uuid=%s) created with %s." % (tunnel.id, tunnel.uuid, tunnel.endpoint[0]))
    self.tunnels[endpoint] = tunnel
    tunnel.start()
    return tunnel, True

class MessageHandler(object):
  def __init__(self, manager, tunnel = None):
    """
    Class constructor.
    
    :param manager: TunnelManager instance
    :param tunnel: Optional Tunnel instance
    """
    self.manager = manager
    self.tunnel = tunnel
  
  def send_message(self, socket, type, data = ""):
    """
    Builds and sends a control message.
    
    :param socket: Socket to use for outgoing messages
    :param type: Message type
    :param data: Optional payload
    """
    socket.send(ControlMessage.build(cs.Container(
      magic1 = 0x80,
      magic2 = 0x73A7,
      version = 1,
      type = type,
      data = data
    )))
  
  def handle(self, socket, data, address):
    """
    Handles a single message of the control protocol.
    
    :param socket: Socket to use for outgoing messages
    :param data: Data that has been received
    :param address: Address where data has been received from
    :return: Message if the message needs further processing, None
      otherwise
    """
    try:
      msg = ControlMessage.parse(data)
    except cs.ConstructError:
      return
    
    # Parsing successful check message type
    if msg.type == CONTROL_TYPE_COOKIE:
      # Cookie request, ensure that the payload is at least 8 bytes, so
      # this protocol will not be a DoS amplifier by spamming with cookies
      if len(msg.data) < 8:
        return
      
      # Respond with a cookie
      msg.data = self.manager.issue_cookie(address)
      socket.sendto(ControlMessage.build(msg), address)
    elif msg.type == CONTROL_TYPE_PREPARE:
      # Parse the prepare message
      try:
        prepare = PrepareMessage.parse(msg.data)
      except cs.ConstructError:
        return
      
      # Check for a cookie match
      if not self.manager.verify_cookie(address, prepare.cookie):
        return
      
      # First check if this tunnel has already been prepared
      tunnel, created = self.manager.setup_tunnel(address, prepare.uuid, prepare.cookie,
        prepare.tunnel_id or 1)
      if tunnel is None:
        msg.type = CONTROL_TYPE_ERROR
        msg.data = ""
        socket.sendto(ControlMessage.build(msg), address)
        return
      
      msg.type = CONTROL_TYPE_TUNNEL
      msg.data = cs.UBInt32("tunnel_id").build(tunnel.id)
      socket.sendto(ControlMessage.build(msg), address)
      
      if self.tunnel is None and created:
        # Clear conntrack tables so all new packets are evaluated against the
        # netfilter rules and so redirected into the tunnel
        tunnel.clear_conntrack()
        
        # Invoke any session up hooks
        tunnel.call_session_up_hooks()
    else:
      # Return the message on any other messages
      return msg

class BaseControl(gevent.Greenlet):
  def __init__(self, config):
    """
    Class constructor.
    
    :param config: Configuration object
    """
    super(BaseControl, self).__init__()
    self.manager = TunnelManager(config)
    self.handler = MessageHandler(self.manager)
    self.closed = False
  
  def close(self):
    """
    Terminates this instance.
    """
    if self.closed:
      return
    
    self.closed = True
    self.manager.close()
    self.kill()
  
  def _run(self):
    """
    Sets up the main control socket and starts processing incoming
    messages.
    """
    # Setup the base control socket that listens for initial incoming
    # tunnel setup requests
    socket = gsocket.socket(gsocket.AF_INET, gsocket.SOCK_DGRAM)
    socket.bind((self.manager.address, self.manager.port))
    
    while True:
      # Wait that some message becomes available from the socket
      try:
        data, address = socket.recvfrom(1024)
      except gsocket.error:
        continue
      
      self.handler.handle(socket, data, address)

if __name__ == '__main__':
  try:
    # We must run as root
    if os.getuid() != 0:
      print "ERROR: Must be root."
      sys.exit(1)
    
    # Parse configuration (first argument must be the location of the configuration
    # file)
    config = ConfigParser.SafeConfigParser()
    try:
      config.read(sys.argv[1])
    except IOError:
      print "ERROR: Failed to open the specified configuration file '%s'!" % sys.argv[1]
      sys.exit(1)
    except IndexError:
      print "ERROR: First argument must be a configuration file path!"
      sys.exit(1)
    
    # Setup the logger
    logging.basicConfig(
      level = logging.DEBUG,
      format = '%(asctime)s %(levelname)-8s %(message)s',
      datefmt = '%a, %d %b %Y %H:%M:%S',
      filename = config.get("log", "filename"),
      filemode = 'a'
    )
    logger = logging.getLogger("tunneldigger.broker")
    
    # Setup the base control server
    base = BaseControl(config)
    base.start()
    gevent.signal(signal.SIGTERM, base.close)
    gevent.signal(signal.SIGINT, base.close)
    
    try:
      base.join()
    except KeyboardInterrupt:
      # SIGINT has been handled and this will cause the application to
      # shutdown, we wait for this to happen and ignore any further
      # interruptions
      while True:
        try:
          base.join()
          break
        except KeyboardInterrupt:
          pass
  except L2TPSupportUnavailable:
    logger.error("L2TP kernel support is not available.")
    sys.exit(1)

