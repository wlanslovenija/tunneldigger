/*
 * Client for our custom L2TPv3 brokerage protocol.
 *
 * Copyright (C) 2012-2014 by Jernej Kos <jernej@kos.mx>
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#include <net/if.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>
#include <netlink/genl/ctrl.h>
#include <netlink/utils.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/genetlink.h>
#include <linux/l2tp.h>

#include "asyncns.h"

// Maximum number of unacknowledged reliable messages.
#define MAX_PENDING_MESSAGES 30

// If this is not defined, build fails on OpenWrt
#define IP_PMTUDISC_PROBE 3

#define L2TP_CONTROL_SIZE 6

// Overhead of IP and UDP headers for measuring PMTU
#define IPV4_HDR_OVERHEAD 28

// L2TP data header overhead for calculating tunnel MTU; takes
// the following headers into account:
//
//   20 bytes (IP header)
//    8 bytes (UDP header)
//    4 bytes (L2TPv3 Session ID)
//    4 bytes (L2TPv3 Cookie)
//    4 bytes (L2TPv3 Pseudowire CE)
//   14 bytes (Ethernet)
//
#define L2TP_TUN_OVERHEAD 54

/* Offset of type field in control messages.
 * 0 means first byte off our payload in l2tp ctrl message */
#define OFFSET_CONTROL_TYPE 4

#ifdef LIBNL_TINY
#define nl_handle nl_sock
#define nl_handle_alloc nl_socket_alloc
#endif

enum l2tp_ctrl_type {
  // Unreliable messages (0x00 - 0x7F)
  CONTROL_TYPE_COOKIE    = 0x01,
  CONTROL_TYPE_PREPARE   = 0x02,
  CONTROL_TYPE_ERROR     = 0x03,
  CONTROL_TYPE_TUNNEL    = 0x04,
  CONTROL_TYPE_KEEPALIVE = 0x05,
  CONTROL_TYPE_PMTUD     = 0x06,
  CONTROL_TYPE_PMTUD_ACK = 0x07,
  CONTROL_TYPE_REL_ACK   = 0x08,

  // Reliable messages (0x80 - 0xFF)
  CONTROL_TYPE_LIMIT     = 0x80,
};

enum l2tp_limit_type {
  LIMIT_TYPE_BANDWIDTH_DOWN = 0x01
};

enum l2tp_ctrl_state {
  STATE_GET_COOKIE,
  STATE_GET_TUNNEL,
  STATE_KEEPALIVE,
  STATE_REINIT,
  STATE_RESOLVING,
};

typedef struct reliable_message {
  uint16_t seqno;
  uint8_t retries;
  time_t timer_rexmit;
  char *msg;
  uint8_t len;

  struct reliable_message *next;
} reliable_message;

typedef struct {
  // UUID
  char *uuid;
  // Tunnel interface name
  char *tunnel_iface;
  // Local tunnel identifer
  int tunnel_id;
  // External hook script
  char *hook;
  // Local IP endpoint
  struct sockaddr_in local_endpoint;
  // Broker hostname
  char *broker_hostname;
  // Broker port (or service name)
  char *broker_port;
  // Broker hostname resolution
  asyncns_query_t *broker_resq;
  struct addrinfo broker_reshints;
  // Tunnel's UDP socket file descriptor
  int fd;
  // Tunnel state
  int state;
  // Cookie
  char cookie[8];
  // Netlink socket
  struct nl_handle *nl_sock;
  int nl_family;
  // Sequence number for reliable messages
  uint16_t reliable_seqno;
  // List of unacked reliable messages
  reliable_message *reliable_unacked;

  // Limits
  uint32_t limit_bandwidth_down;

  // Tunnel uptime
  time_t tunnel_up_since;

  // Should the context only be used as a standby context
  int standby_only;
  int standby_available;

  // PMTU probing
  int pmtu;
  int probed_pmtu;
  time_t pmtu_reprobe_interval;
  time_t timer_pmtu_reprobe;
  time_t timer_pmtu_collect;
  time_t timer_pmtu_xmit;

  // Last keepalive and timers
  time_t last_alive;
  time_t timer_cookie;
  time_t timer_tunnel;
  time_t timer_keepalive;
  time_t timer_reinit;
  time_t timer_resolving;
} l2tp_context;

// Forward declarations
void context_delete_tunnel(l2tp_context *ctx);
void context_close_tunnel(l2tp_context *ctx);
void context_send_packet(l2tp_context *ctx, uint8_t type, char *payload, uint8_t len);
void context_send_raw_packet(l2tp_context *ctx, char *packet, uint8_t len);
void context_send_reliable_packet(l2tp_context *ctx, uint8_t type, char *payload, uint8_t len);
int context_setup_tunnel(l2tp_context *ctx, uint32_t peer_tunnel_id);
void context_free(l2tp_context *ctx);

static l2tp_context *main_context = NULL;
static asyncns_t *asyncns_context = NULL;

/* Force the tunnel to go over a certain interface */
char *force_iface = 0;

time_t timer_now()
{
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
    syslog(LOG_ERR, "Failed to get monotonic clock, weird things may happen!");
    return -1;
  }
  return ts.tv_sec;
}

int is_timeout(time_t *timer, time_t period)
{
  if (*timer < 0)
    return 0;

  time_t now = timer_now();
  if (now - *timer > period) {
    *timer = now;
    return 1;
  }

  return 0;
}

uint8_t parse_u8(unsigned char **buffer)
{
  uint8_t value = *((uint8_t*) *buffer);
  (*buffer) += sizeof(uint8_t);
  return value;
}

uint16_t parse_u16(unsigned char **buffer)
{
  uint16_t value = ntohs(*((uint16_t*) *buffer));
  (*buffer) += sizeof(uint16_t);
  return value;
}

uint32_t parse_u32(unsigned char **buffer)
{
  uint32_t value = ntohl(*((uint32_t*) *buffer));
  (*buffer) += sizeof(uint32_t);
  return value;
}

void put_u8(unsigned char **buffer, uint8_t value)
{
  (*buffer)[0] = (unsigned char) value;
  (*buffer) += sizeof(value);
}

void put_u16(unsigned char **buffer, uint16_t value)
{
  (*buffer)[0] = value >> 8;
  (*buffer)[1] = value;
  (*buffer) += sizeof(value);
}

void put_u32(unsigned char **buffer, uint32_t value)
{
  (*buffer)[0] = value >> 24;
  (*buffer)[1] = value >> 16;
  (*buffer)[2] = value >> 8;
  (*buffer)[3] = value;
  (*buffer) += sizeof(value);
}

l2tp_context *context_new(char *uuid, const char *local_ip, const char *broker_hostname,
  char *broker_port, char *tunnel_iface, char *hook, int tunnel_id, int limit_bandwidth_down)
{
  l2tp_context *ctx = (l2tp_context*) calloc(1, sizeof(l2tp_context));
  if (!ctx) {
    syslog(LOG_ERR, "Failed to allocate memory for context!");
    return NULL;
  }

  ctx->state = STATE_REINIT;

  ctx->local_endpoint.sin_family = AF_INET;
  ctx->local_endpoint.sin_port = 0;
  if (inet_aton(local_ip, &ctx->local_endpoint.sin_addr.s_addr) < 0) {
    syslog(LOG_ERR, "Failed to parse local endpoint!");
    goto free_and_return;
  }

  ctx->broker_hostname = strdup(broker_hostname);
  ctx->broker_port = strdup(broker_port);

  ctx->uuid = strdup(uuid);
  ctx->tunnel_iface = strdup(tunnel_iface);
  ctx->tunnel_id = tunnel_id;
  ctx->hook = hook ? strdup(hook) : NULL;

  // Reset limits
  ctx->limit_bandwidth_down = (uint32_t) limit_bandwidth_down;

  // Setup the netlink socket
  ctx->nl_sock = nl_handle_alloc();
  if (!ctx->nl_sock) {
    syslog(LOG_ERR, "Failed to allocate a netlink socket!");
    goto free_and_return;
  }

  if (nl_connect(ctx->nl_sock, NETLINK_GENERIC) < 0) {
    syslog(LOG_ERR, "Failed to connect to netlink!");
    goto free_and_return;
  }

  ctx->nl_family = genl_ctrl_resolve(ctx->nl_sock, L2TP_GENL_NAME);
  if (ctx->nl_family < 0) {
    syslog(LOG_ERR, "Failed to resolve L2TP netlink interface - check if L2TP kernel modules are loaded!");
    goto free_and_return;
  }

  return ctx;
free_and_return:
  context_free(ctx);
  return NULL;
}

int context_reinitialize(l2tp_context *ctx)
{
  /* We have to set this state here to be sure ctx is in a sane state when this functions fails(ret -1)
   * because other functions than the state machine call this function.
   */
  ctx->state = STATE_REINIT;

  if (ctx->fd > 0)
    close(ctx->fd);
  ctx->fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (ctx->fd < 0)
    return -1;

  /* Bind the socket to an interface if given */
  if (force_iface) {
    int rc;

    rc = setsockopt(ctx->fd, SOL_SOCKET, SO_BINDTODEVICE, force_iface, strlen(force_iface));
    if (rc != 0) {
      syslog(LOG_ERR, "Failed to bind to device!");
      return -1;
    }
  }

  if (bind(ctx->fd, (struct sockaddr*) &ctx->local_endpoint, sizeof(ctx->local_endpoint)) < 0) {
    syslog(LOG_ERR, "Failed to bind to local endpoint - check WAN connectivity!");
    return -1;
  }

  int val = IP_PMTUDISC_PROBE;
  if (setsockopt(ctx->fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val)) < 0)
    return -1;

  ctx->standby_only = 1;
  ctx->standby_available = 0;
  ctx->reliable_seqno = 0;
  while (ctx->reliable_unacked != NULL) {
    reliable_message *next = ctx->reliable_unacked->next;
    free(ctx->reliable_unacked->msg);
    free(ctx->reliable_unacked);
    ctx->reliable_unacked = next;
  }
  if (ctx->broker_resq)
    asyncns_cancel(asyncns_context, ctx->broker_resq);
  ctx->broker_resq = NULL;

  // Reset relevant timers
  time_t now = timer_now();
  ctx->timer_cookie = now;
  ctx->timer_tunnel = now;
  ctx->timer_keepalive = now;
  ctx->timer_reinit = now;
  ctx->timer_resolving = -1;

  // PMTU discovery
  ctx->pmtu = 0;
  ctx->probed_pmtu = 0;
  ctx->pmtu_reprobe_interval = 15;
  ctx->timer_pmtu_reprobe = now;
  ctx->timer_pmtu_collect = -1;
  ctx->timer_pmtu_xmit = -1;

  ctx->state = STATE_RESOLVING;

  // Ensure any tunnels are removed.
  context_delete_tunnel(ctx);

  return 0;
}

void context_start_connect(l2tp_context *ctx)
{
  if (ctx->state != STATE_RESOLVING)
    return;

  memset(&ctx->broker_reshints, 0, sizeof(struct addrinfo));
  ctx->broker_reshints.ai_family = AF_INET;
  ctx->broker_reshints.ai_socktype = SOCK_DGRAM;
  ctx->broker_resq = asyncns_getaddrinfo(asyncns_context, ctx->broker_hostname, ctx->broker_port,
    &ctx->broker_reshints);
  ctx->timer_resolving = timer_now();

  if (!ctx->broker_resq) {
    syslog(LOG_ERR, "Failed to start name resolution!");
    return;
  }
}

void context_call_hook(l2tp_context *ctx, const char *hook)
{
  if (ctx->hook == NULL)
    return;

  int pid = fork();
  if (pid == 0) {
    execl(ctx->hook, ctx->hook, hook, ctx->tunnel_iface, (char*) NULL);
    exit(1);
  }
}

void context_limit_send_simple_request(l2tp_context *ctx, uint8_t type, uint32_t limit)
{
  char buffer[16];
  unsigned char *buf = (unsigned char*) &buffer;

  put_u8(&buf, type);
  // Simple request are always a single 4 byte integer
  put_u8(&buf, 4);
  put_u32(&buf, limit);

  // Now send the packet
  context_send_reliable_packet(ctx, CONTROL_TYPE_LIMIT, (char*) &buffer, 6);
}

void context_setup_limits(l2tp_context *ctx)
{
  // Configure downstream bandwidth limit
  if (ctx->limit_bandwidth_down > 0) {
    syslog(LOG_INFO, "Requesting the broker to configure downstream bandwidth limit of %d kbps.",
      ctx->limit_bandwidth_down);
    context_limit_send_simple_request(ctx, LIMIT_TYPE_BANDWIDTH_DOWN, ctx->limit_bandwidth_down);
  }
}

void context_process_control_packet(l2tp_context *ctx)
{
  char buffer[2048];
  struct sockaddr_in endpoint;
  socklen_t endpoint_len = sizeof(endpoint);
  ssize_t bytes = recvfrom(ctx->fd, &buffer, sizeof(buffer), 0, (struct sockaddr*) &endpoint,
    &endpoint_len);

  if (bytes < 0)
    return;

  // Decode packet header
  unsigned char *buf = (unsigned char*) &buffer;
  if (parse_u8(&buf) != 0x80 || parse_u16(&buf) != 0x73A7)
    return;

  // Check version number
  if (parse_u8(&buf) != 1)
    return;

  uint8_t type = parse_u8(&buf);
  uint8_t payload_length = parse_u8(&buf);

  // Each received packet counts as a liveness indicator
  ctx->last_alive = timer_now();

  // Check packet type
  switch (type) {
    case CONTROL_TYPE_COOKIE: {
      if (ctx->state == STATE_GET_COOKIE) {
        memcpy(&ctx->cookie, buf, payload_length);

        // Mark the connection as being available for later establishment
        ctx->standby_available = 1;

        // Only switch to tunnel establishment state if the context is
        // not in standby-only state
        if (!ctx->standby_only)
          ctx->state = STATE_GET_TUNNEL;
      }
      break;
    }
    case CONTROL_TYPE_ERROR: {
      if (ctx->state == STATE_GET_TUNNEL) {
        syslog(LOG_WARNING, "Received error response from broker!");
        ctx->state = STATE_GET_COOKIE;
      } else if (ctx->state == STATE_KEEPALIVE) {
        syslog(LOG_ERR, "Broker sent us a teardown request, closing tunnel!");
        context_close_tunnel(ctx);
      }
      break;
    }
    case CONTROL_TYPE_TUNNEL: {
      if (ctx->state == STATE_GET_TUNNEL) {
        if (context_setup_tunnel(ctx, parse_u32(&buf)) < 0) {
          syslog(LOG_ERR, "Unable to create local L2TP tunnel!");
          ctx->state = STATE_GET_COOKIE;
        } else {
          syslog(LOG_INFO, "Tunnel successfully established.");
          context_call_hook(ctx, "session.up");
          ctx->tunnel_up_since = timer_now();
          ctx->state = STATE_KEEPALIVE;
          context_setup_limits(ctx);
        }
      }
      break;
    }
    case CONTROL_TYPE_KEEPALIVE: break;
    case CONTROL_TYPE_PMTUD: {
      if (ctx->state == STATE_KEEPALIVE) {
        // Send back an acknowledgement packet with proper size
        char buffer[16];
        unsigned char *buf = (unsigned char*) &buffer;
        put_u16(&buf, bytes);
        context_send_packet(ctx, CONTROL_TYPE_PMTUD_ACK, (char*) &buffer, 2);
      }
      break;
    }
    case CONTROL_TYPE_PMTUD_ACK: {
      if (ctx->state == STATE_KEEPALIVE) {
        // Process a PMTU probe
        uint16_t psize = parse_u16(&buf) + IPV4_HDR_OVERHEAD;
        if (psize > ctx->probed_pmtu)
          ctx->probed_pmtu = psize;
      }
      break;
    }
    case CONTROL_TYPE_REL_ACK: {
      // ACK of a reliable message
      uint16_t seqno = parse_u16(&buf);
      reliable_message *msg = ctx->reliable_unacked;
      reliable_message *prev = NULL;
      while (msg != NULL) {
        if (msg->seqno == seqno) {
          // Remove from list
          if (prev == NULL) {
            ctx->reliable_unacked = msg->next;
          } else {
            prev->next = msg->next;
          }

          free(msg->msg);
          free(msg);
          return;
        }

        prev = msg;
        msg = msg->next;
      }
      break;
    }
    default: return;
  }
}

void context_prepare_packet(l2tp_context *ctx, unsigned char *buf, uint8_t type, char *payload, uint8_t len)
{
  put_u8(&buf, 0x80);
  put_u16(&buf, 0x73A7);
  put_u8(&buf, 1);
  put_u8(&buf, type);
  put_u8(&buf, len);
  if (payload)
    memcpy(buf, payload, len);
}

void context_send_reliable_packet(l2tp_context *ctx, uint8_t type, char *payload, uint8_t len)
{
  char *packet = (char*) malloc(L2TP_CONTROL_SIZE + len + 2);
  char buffer[512];
  unsigned char *buf = (unsigned char*) &buffer;

  put_u16(&buf, ctx->reliable_seqno);
  memcpy(buf, payload, len);
  context_prepare_packet(ctx, packet, type, (char*) &buffer, len + 2);

  // Store packet to unacked list
  reliable_message *msg = (reliable_message*) malloc(sizeof(reliable_message));
  msg->seqno = ctx->reliable_seqno;
  msg->retries = 0;
  msg->timer_rexmit = timer_now();
  msg->msg = packet;
  msg->len = L2TP_CONTROL_SIZE + len + 2;
  msg->next = NULL;

  size_t pending_messages = 0;
  if (ctx->reliable_unacked == NULL) {
    ctx->reliable_unacked = msg;
  } else {
    reliable_message *m = ctx->reliable_unacked;
    while (m->next != NULL) {
      m = m->next;
      pending_messages++;
    }

    m->next = msg;
  }

  // If there are too many unacked messages, start dropping old ones.
  if (pending_messages > MAX_PENDING_MESSAGES) {
    reliable_message *m = ctx->reliable_unacked;
    ctx->reliable_unacked = m->next;
    free(m->msg);
    free(m);
  }

  ctx->reliable_seqno++;
  context_send_raw_packet(ctx, msg->msg, msg->len);
}

void context_send_raw_packet(l2tp_context *ctx, char *packet, uint8_t len)
{
  if (send(ctx->fd, packet, len, 0) < 0) {
    switch (errno) {
      case EINVAL: {
        // This may happen when the underlying interface is removed. In this case we
        // need to bind the socket again and re-initialize the context.
        syslog(LOG_WARNING, "Failed to send() control packet, interface disappeared?");
        syslog(LOG_WARNING, "Forcing tunnel reinitialization.");
        ctx->state = STATE_REINIT;
        break;
      }
      default: {
        syslog(LOG_WARNING, "Failed to send() control packet (errno=%d, type=%x)!", errno, packet[OFFSET_CONTROL_TYPE]);
        break;
      }
    }
  }
}

void context_send_packet(l2tp_context *ctx, uint8_t type, char *payload, uint8_t len)
{
  char buffer[2048];
  context_prepare_packet(ctx, (unsigned char*) &buffer, type, payload, len);

  // Pad the packet to 12 bytes to avoid it being filtered by some firewalls
  // when used over port 53
  if (L2TP_CONTROL_SIZE + len < 12)
    len += 12 - L2TP_CONTROL_SIZE - len;

  // Send the packet
  context_send_raw_packet(ctx, (char*) &buffer, L2TP_CONTROL_SIZE + len);
}

void context_send_pmtu_probe(l2tp_context *ctx, size_t size)
{
  char buffer[2048];
  if (size > 1500 || size < L2TP_CONTROL_SIZE)
    return;

  unsigned char *buf = (unsigned char*) &buffer;
  put_u8(&buf, 0x80);
  put_u16(&buf, 0x73A7);
  put_u8(&buf, 1);
  put_u8(&buf, CONTROL_TYPE_PMTUD);
  put_u8(&buf, 0);

  // Send the packet
  if (send(ctx->fd, &buffer, size - IPV4_HDR_OVERHEAD, 0) < 0) {
    syslog(LOG_WARNING, "Failed to send() PMTU probe packet (errno=%d)!", errno);
  }
}

void context_pmtu_start_discovery(l2tp_context *ctx)
{
  size_t sizes[] = {
    1334, 1400, 1450, 1476, 1492, 1500
  };

  int i;
  for (i = 0; i < 6; i++) {
    context_send_pmtu_probe(ctx, sizes[i]);
  }
}

void context_send_setup_request(l2tp_context *ctx)
{
  char buffer[512];
  unsigned char *buf = (unsigned char*) &buffer;

  // First 8 bytes of payload is the cookie value
  memcpy(buf, ctx->cookie, 8);
  buf += 8;

  // Then comes the size-prefixed UUID
  size_t uuid_len = strlen(ctx->uuid);
  if (uuid_len > 255)
    uuid_len = 255;

  put_u8(&buf, uuid_len);
  memcpy(buf, ctx->uuid, uuid_len);
  buf += uuid_len;

  // And the local tunnel identifier at the end
  put_u16(&buf, ctx->tunnel_id);

  // Now send the packet
  context_send_packet(ctx, CONTROL_TYPE_PREPARE, (char*) &buffer, uuid_len + 9);
}

void context_delete_tunnel(l2tp_context *ctx)
{
  // Take the interface down.
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ctx->tunnel_iface, sizeof(ifr.ifr_name));
  if (ioctl(ctx->fd, SIOCGIFFLAGS, &ifr) == 0) {
    ifr.ifr_flags &= ~IFF_UP;
    if (ioctl(ctx->fd, SIOCSIFFLAGS, &ifr) < 0) {
      syslog(LOG_WARNING, "Failed to take down interface %s (errno=%d).", ifr.ifr_name, errno);
    }
  }

  // Delete the session
  struct nl_msg *msg = nlmsg_alloc();
  genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->nl_family, 0, NLM_F_REQUEST,
    L2TP_CMD_SESSION_DELETE, L2TP_GENL_VERSION);

  nla_put_u32(msg, L2TP_ATTR_CONN_ID, ctx->tunnel_id);
  nla_put_u32(msg, L2TP_ATTR_SESSION_ID, 1);

  nl_send_auto_complete(ctx->nl_sock, msg);
  nlmsg_free(msg);
  nl_wait_for_ack(ctx->nl_sock);

  // Delete the tunnel
  msg = nlmsg_alloc();
  genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->nl_family, 0, NLM_F_REQUEST,
    L2TP_CMD_TUNNEL_DELETE, L2TP_GENL_VERSION);

  nla_put_u32(msg, L2TP_ATTR_CONN_ID, ctx->tunnel_id);

  nl_send_auto_complete(ctx->nl_sock, msg);
  nlmsg_free(msg);
  nl_wait_for_ack(ctx->nl_sock);
}

int context_setup_tunnel(l2tp_context *ctx, uint32_t peer_tunnel_id)
{
  // Create a tunnel
  struct nl_msg *msg = nlmsg_alloc();
  genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->nl_family, 0, NLM_F_REQUEST,
    L2TP_CMD_TUNNEL_CREATE, L2TP_GENL_VERSION);

  nla_put_u32(msg, L2TP_ATTR_CONN_ID, ctx->tunnel_id);
  nla_put_u32(msg, L2TP_ATTR_PEER_CONN_ID, peer_tunnel_id);
  nla_put_u8(msg, L2TP_ATTR_PROTO_VERSION, 3);
  nla_put_u16(msg, L2TP_ATTR_ENCAP_TYPE, L2TP_ENCAPTYPE_UDP);
  nla_put_u32(msg, L2TP_ATTR_FD, ctx->fd);

  nl_send_auto_complete(ctx->nl_sock, msg);
  nlmsg_free(msg);

  int result = nl_wait_for_ack(ctx->nl_sock);
  if (result < 0)
    return -1;

  // Create a session (currently only a single session is supported)
  msg = nlmsg_alloc();
  genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->nl_family, 0, NLM_F_REQUEST,
    L2TP_CMD_SESSION_CREATE, L2TP_GENL_VERSION);

  nla_put_u32(msg, L2TP_ATTR_CONN_ID, ctx->tunnel_id);
  nla_put_u32(msg, L2TP_ATTR_SESSION_ID, 1);
  nla_put_u32(msg, L2TP_ATTR_PEER_SESSION_ID, 1);
  nla_put_u16(msg, L2TP_ATTR_PW_TYPE, L2TP_PWTYPE_ETH);
  nla_put_string(msg, L2TP_ATTR_IFNAME, ctx->tunnel_iface);

  nl_send_auto_complete(ctx->nl_sock, msg);
  nlmsg_free(msg);

  result = nl_wait_for_ack(ctx->nl_sock);
  if (result < 0)
    return -1;

  return 0;
}

int context_session_set_mtu(l2tp_context *ctx, uint16_t mtu)
{
  // Update the device MTU
  struct ifreq ifr;

  if (mtu < 1280)
    mtu = 1280;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ctx->tunnel_iface, sizeof(ifr.ifr_name));
  ifr.ifr_mtu = mtu;
  if (ioctl(ctx->fd, SIOCSIFMTU, &ifr) < 0) {
    syslog(LOG_WARNING, "Failed to set MTU to %d on device %s (errno=%d)!", (int) mtu,
      ifr.ifr_name, errno);
    return -1;
  }

  // Update session parameters
  struct nl_msg *msg = nlmsg_alloc();
  genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->nl_family, 0, NLM_F_REQUEST,
    L2TP_CMD_SESSION_MODIFY, L2TP_GENL_VERSION);

  nla_put_u32(msg, L2TP_ATTR_CONN_ID, ctx->tunnel_id);
  nla_put_u32(msg, L2TP_ATTR_SESSION_ID, 1);
  nla_put_u16(msg, L2TP_ATTR_MTU, mtu);

  nl_send_auto_complete(ctx->nl_sock, msg);
  nlmsg_free(msg);
  nl_wait_for_ack(ctx->nl_sock);

  return 0;
}

void context_close_tunnel(l2tp_context *ctx)
{
  // Notify the broker that the tunnel has been closed
  context_send_packet(ctx, CONTROL_TYPE_ERROR, NULL, 0);

  // Call down hook, delete the tunnel and set state to reinit
  context_call_hook(ctx, "session.down");
  context_delete_tunnel(ctx);
  ctx->state = STATE_REINIT;
}

void context_process(l2tp_context *ctx)
{
  // Poll the file descriptor to see if anything is to be read/written
  fd_set rfds;
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;

  FD_ZERO(&rfds);
  FD_SET(ctx->fd, &rfds);

  // Add descriptor for DNS resolution
  int nsfd = asyncns_fd(asyncns_context);
  int nfds = nsfd > ctx->fd ? nsfd : ctx->fd;
  FD_SET(nsfd, &rfds);

  int res = select(nfds + 1, &rfds, NULL, NULL, &tv);
  if (res == -1) {
    return;
  } else if (res) {
    if (FD_ISSET(ctx->fd, &rfds))
      context_process_control_packet(ctx);
    else if (FD_ISSET(nsfd, &rfds))
      asyncns_wait(asyncns_context, 0);
  }

  // Transmit packets if needed
  switch (ctx->state) {
    case STATE_RESOLVING: {
      if (ctx->broker_resq == NULL)
        context_start_connect(ctx);

      // Check if address has already been resolved and change state
      if (ctx->broker_resq && asyncns_isdone(asyncns_context, ctx->broker_resq)) {
        struct addrinfo *result;
        int status = asyncns_getaddrinfo_done(asyncns_context, ctx->broker_resq, &result);

        if (status != 0) {
          syslog(LOG_ERR, "Failed to resolve hostname '%s'.", ctx->broker_hostname);
          /* TODO: memory leak - asyncns_getaddrinfo_done() does not free in all error cases ctx->broker_resp.
           * Fix asyncns - remove free() from asyncns_getaddrinfo_done()
           */
          ctx->broker_resq = NULL;
          ctx->state = STATE_REINIT;
          return;
        } else {
          if (connect(ctx->fd, result->ai_addr, result->ai_addrlen) < 0) {
            syslog(LOG_ERR, "Failed to connect to remote endpoint - check WAN connectivity!");
            ctx->state = STATE_REINIT;
          } else {
            ctx->state = STATE_GET_COOKIE;
          }
          asyncns_freeaddrinfo(result);
          ctx->broker_resq = NULL;
        }
      } else if (is_timeout(&ctx->timer_resolving, 5)) {
        syslog(LOG_ERR, "Hostname resolution timed out.");

        if (ctx->broker_resq)
          asyncns_cancel(asyncns_context, ctx->broker_resq);
        ctx->broker_resq = NULL;
        ctx->state = STATE_REINIT;
        return;
      }
      break;
    }
    case STATE_GET_COOKIE: {
      // Send request for a tasty cookie
      if (is_timeout(&ctx->timer_cookie, 2))
        context_send_packet(ctx, CONTROL_TYPE_COOKIE, "XXXXXXXX", 8);
      break;
    }
    case STATE_GET_TUNNEL: {
      // Send tunnel setup request
      if (is_timeout(&ctx->timer_tunnel, 2))
        context_send_setup_request(ctx);
      break;
    }
    case STATE_KEEPALIVE: {
      // Send periodic keepalive messages
      if (is_timeout(&ctx->timer_keepalive, 5))
        context_send_packet(ctx, CONTROL_TYPE_KEEPALIVE, NULL, 0);

      // Send periodic PMTU probes
      if (is_timeout(&ctx->timer_pmtu_reprobe, ctx->pmtu_reprobe_interval)) {
        ctx->probed_pmtu = 0;
        ctx->timer_pmtu_collect = timer_now();
        ctx->timer_pmtu_xmit = timer_now();
        context_pmtu_start_discovery(ctx);
        ctx->pmtu_reprobe_interval *= 2;
        if (ctx->pmtu_reprobe_interval > 600)
          ctx->pmtu_reprobe_interval = 600;
      }

      // Check if we need to collect PMTU probes
      if (is_timeout(&ctx->timer_pmtu_collect, 5)) {
        if (ctx->probed_pmtu > 0 && ctx->probed_pmtu != ctx->pmtu) {
          ctx->pmtu = ctx->probed_pmtu;
          context_session_set_mtu(ctx, ctx->pmtu - L2TP_TUN_OVERHEAD);
        }

        ctx->probed_pmtu = 0;
        ctx->timer_pmtu_collect = -1;
        ctx->timer_pmtu_xmit = -1;
      }

      if (is_timeout(&ctx->timer_pmtu_xmit, 1))
        context_pmtu_start_discovery(ctx);

      // Check if we need to attempt to retransmit any reliable messages
      reliable_message *msg = ctx->reliable_unacked;
      reliable_message *prev = NULL;
      while (msg != NULL) {
        if (is_timeout(&msg->timer_rexmit, 1)) {
          if (++msg->retries >= 10) {
            syslog(LOG_WARNING, "Dropping message that has been retried too many times.");

            if (prev != NULL) {
              prev->next = msg->next;
            } else {
              ctx->reliable_unacked = msg->next;
            }

            msg = msg->next;
            continue;
          }

          context_send_raw_packet(ctx, msg->msg, msg->len);
        }

        prev = msg;
        msg = msg->next;
      }

      // Check if the tunnel is still alive
      if (timer_now() - ctx->last_alive > 60) {
        syslog(LOG_WARNING, "Tunnel has timed out, closing down interface.");
        context_close_tunnel(ctx);
      }
      break;
    }
    case STATE_REINIT: {
      if (is_timeout(&ctx->timer_reinit, 15)) {
        syslog(LOG_INFO, "Reinitializing tunnel context.");
        if (context_reinitialize(ctx) < 0) {
          syslog(LOG_ERR, "Unable to reinitialize the context!");
        } else {
          context_start_connect(ctx);
        }
      }
      break;
    }
  }
}

void context_free(l2tp_context *ctx)
{
  if (!ctx) {
    return;
  }

  free(ctx->uuid);
  free(ctx->tunnel_iface);
  free(ctx->hook);
  free(ctx->broker_hostname);
  free(ctx->broker_port);
  free(ctx);
}

void term_handler(int signum)
{
  (void) signum; /* unused */

  syslog(LOG_WARNING, "Got termination signal, shutting down tunnel...");

  if (main_context) {
    context_close_tunnel(main_context);
    main_context = NULL;
  }

  exit(1);
}

void child_handler(int signum)
{
  (void) signum; /* unused */

  int status;
  waitpid(-1, &status, WNOHANG);
}

void show_help(const char *app)
{
  fprintf(stderr, "usage: %s [options]\n", app);
  fprintf(stderr,
    "       -h            this text\n"
    "       -f            don't daemonize into background\n"
    "       -u uuid       set UUID string\n"
    "       -l ip         local IP address to bind to (default 0.0.0.0)\n"
    "       -b host:port  broker hostname and port (can be specified multiple times)\n"
    "       -i iface      tunnel interface name\n"
    "       -I iface      force client to bind tunnel socket to a specific interface\n"
    "       -s hook       hook script\n"
    "       -t id         local tunnel id (default 1)\n"
    "       -L limit      request broker to set downstream bandwidth limit (in kbps)\n"
  );
}

int main(int argc, char **argv)
{
  // Check for root permissions
  if (getuid() != 0) {
    fprintf(stderr, "ERROR: Root access is required to setup tunnels!\n");
    return 1;
  }

  // Install signal handlers
  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, term_handler);
  signal(SIGTERM, term_handler);
  signal(SIGCHLD, child_handler);

  // Parse program options
  int log_option = 0;
  char *uuid = NULL, *local_ip = "0.0.0.0", *tunnel_iface = NULL;
  char *hook = NULL;
  int tunnel_id = 1;
  int limit_bandwidth_down = 0;

  // List of brokers
  typedef struct {
    char *address;
    char *port;
    l2tp_context *ctx;
  } broker_cfg;
#define MAX_BROKERS 10

  broker_cfg brokers[MAX_BROKERS];
  int broker_cnt = 0;

  char c;
  while ((c = getopt(argc, argv, "hfu:l:b:p:i:s:t:L:I:")) != EOF) {
    switch (c) {
      case 'h': {
        show_help(argv[0]);
        return 1;
      }
      case 'f': log_option |= LOG_PERROR; break;
      case 'u': uuid = strdup(optarg); break;
      case 'l': local_ip = strdup(optarg); break;
      case 'b': {
        if (broker_cnt >= MAX_BROKERS) {
          fprintf(stderr, "ERROR: You cannot specify more than %d brokers!\n", MAX_BROKERS);
          return 1;
        }

        char *address = strtok(optarg, ":");
        char *port = strtok(NULL, ":");
        if (!address || !port) {
          fprintf(stderr, "ERROR: Each broker must be passed in the format 'host:port'!\n");
          return 1;
        }

        brokers[broker_cnt].address = strdup(address);
        brokers[broker_cnt].port = strdup(port);
        brokers[broker_cnt].ctx = NULL;
        broker_cnt++;
        break;
      }
      case 'i': tunnel_iface = strdup(optarg); break;
      case 's': hook = strdup(optarg); break;
      case 't': tunnel_id = atoi(optarg); break;
      case 'L': limit_bandwidth_down = atoi(optarg); break;
      case 'I': force_iface = strdup(optarg); break;
      default: {
        fprintf(stderr, "ERROR: Invalid option %c!\n", c);
        show_help(argv[0]);
        return 1;
      }
    }
  }

  if (!uuid || broker_cnt < 1 || !tunnel_iface) {
    fprintf(stderr, "ERROR: UUID, tunnel interface and broker list are required options!\n");
    show_help(argv[0]);
    return 1;
  }

  // Open the syslog facility
  openlog("td-client", log_option, LOG_DAEMON);

  // Initialize the async DNS resolver
  if (!(asyncns_context = asyncns_new(2))) {
    syslog(LOG_ERR, "Unable to initialize DNS resolver!");
    return 1;
  }

  // Initialize contexts for all configured brokers in standby mode
  int i;
  for (i = 0; i < broker_cnt; i++) {
    // Attempt to initialize the L2TP context. This might fail because the network is still
    // unreachable or if the L2TP kernel modules are not loaded. We will retry for 5 minutes
    // and then abort.
    int tries = 0;
    for (;;) {
      brokers[i].ctx = context_new(uuid, local_ip, brokers[i].address, brokers[i].port,
        tunnel_iface, hook, tunnel_id, limit_bandwidth_down);

      if (!brokers[i].ctx) {
        syslog(LOG_ERR, "Unable to initialize tunneldigger context! Retrying in 5 seconds...");
        sleep(5);
        continue;
      }

      // Context successfully initialized
      break;
    }
  }

  for (;;) {
    /* make sure all brokers are in sane state */
    for (i = 0; i < broker_cnt; i++) {
      context_reinitialize(brokers[i].ctx);
    }

    syslog(LOG_INFO, "Performing broker selection...");

    // Reset availability information and standby setting
    for (i = 0; i < broker_cnt; i++) {
      // Start hostname resolution and connect process
      context_start_connect(brokers[i].ctx);
    }

    // Perform broker processing for 20 seconds or until all brokers are ready
    // (whichever is shorter); since all contexts are in standby mode, all
    // available connections will be stuck in GET_COOKIE state
    time_t timer_collect = timer_now();
    for (;;) {
      int ready_cnt = 0;
      for (i = 0; i < broker_cnt; i++) {
        context_process(brokers[i].ctx);
      }

      for (i = 0; i < broker_cnt; i++) {
        ready_cnt += brokers[i].ctx->standby_available ? 1 : 0;
      }

      if (ready_cnt == broker_cnt || (is_timeout(&timer_collect, 20) && ready_cnt > 0))
        break;
    }

    // Select the first available broker and use it to establish a tunnel
    for (i = 0; i < broker_cnt; i++) {
      if (brokers[i].ctx->standby_available) {
        brokers[i].ctx->standby_only = 0;
        main_context = brokers[i].ctx;
        break;
      }
    }

    syslog(LOG_INFO, "Selected %s:%s as the best broker.", brokers[i].address,
      brokers[i].port);

    // Perform processing on the main context; if the connection fails and does
    // not recover after 30 seconds, restart the broker selection process
    int restart_timer = 0;
    time_t timer_establish = timer_now();
    for (;;) {
      context_process(main_context);

      if (main_context->state == STATE_REINIT) {
        syslog(LOG_ERR, "Connection to %s lost.", main_context->broker_hostname);
        break;
      }

      // If the connection is lost, we start the reconnection timer
      if (restart_timer && main_context->state != STATE_KEEPALIVE) {
        timer_establish = timer_now();
        restart_timer = 0;
      }

      // After 30 seconds, we check if the tunnel has been established
      if (is_timeout(&timer_establish, 30)) {
        if (main_context->state != STATE_KEEPALIVE) {
          // Tunnel is not established yet, skip to the next broker
          syslog(LOG_ERR, "Connection with broker not established after 30 seconds, restarting broker selection...");
          break;
        }

        timer_establish = -1;
        restart_timer = 1;
      }
    }

    // If we are here, the connection has been lost
    main_context = NULL;
  }

  if (asyncns_context)
    asyncns_free(asyncns_context);

  return 0;
}

