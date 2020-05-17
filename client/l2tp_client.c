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

#ifdef USE_SHARED_LIBASYNCNS
#include <asyncns.h>
#else
#include "libasyncns/asyncns.h"
#endif

// Maximum number of unacknowledged reliable messages.
#define MAX_PENDING_MESSAGES 30

// If this is not defined, build fails on OpenWrt.
#define IP_PMTUDISC_PROBE 3

#define L2TP_CONTROL_SIZE 6

// Overhead of IP and UDP headers for measuring PMTU.
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

enum l2tp_ctrl_type {
  // Unreliable messages (0x00 - 0x7F).
  CONTROL_TYPE_COOKIE    = 0x01,
  CONTROL_TYPE_PREPARE   = 0x02,
  CONTROL_TYPE_ERROR     = 0x03,
  CONTROL_TYPE_TUNNEL    = 0x04,
  CONTROL_TYPE_KEEPALIVE = 0x05,
  CONTROL_TYPE_PMTUD     = 0x06,
  CONTROL_TYPE_PMTUD_ACK = 0x07,
  CONTROL_TYPE_REL_ACK   = 0x08,
  CONTROL_TYPE_PMTU_NTFY = 0x09,
  CONTROL_TYPE_USAGE     = 0x0A,

  // Reliable messages (0x80 - 0xFF).
  CONTROL_TYPE_LIMIT     = 0x80,
};

enum l2tp_error_type {
  ERROR_REASON_OTHER_REQUEST  = 0x00,
  ERROR_REASON_SHUTDOWN       = 0x01,
  ERROR_REASON_TIMEOUT        = 0x02,
  ERROR_REASON_FAILURE        = 0x03,
};

enum l2tp_error_direction {
  ERROR_DIRECTION_SERVER = 0x00,
  ERROR_DIRECTION_CLIENT = 0x10,
};

enum l2tp_limit_type {
  LIMIT_TYPE_BANDWIDTH_DOWN = 0x01
};

/* The state machine looks as follows:
   STATE_REINIT (initial state)
   When the FD is successfully initialized:
   -> STATE_RESOLVING
   When DNS resolving succeeds:
   -> STATE_GET_USAGE (sending a usage and a cookie request every 2s)
   when we receive usage information or a cookie
   -> STATE_STANBDY

   Now broker selection is performed; for the selected broker the main loop changes the state so
   that we go on:
   -> STATE_GET_COOKIE (sending a cookie request every 2s)
   when we receive the cookie
   -> STATE_GET_TUNNEL
   when we receive the tunnel information
   -> STATE_KEEPALIVE
   when the connection fails
   -> STATE_FAILED

   In case of an error, we transition to STATE_REINIT (if it happens early) or STATE_FAILED
   (if it happens when we are already >= STATE_GET_COOKIE).  The main loop restarts everything
   once the selected broker enters STATE_FAILED.
   For broken brokers, the main loop sets the state to STATE_FAILED to make sure that
   they do not do anything.
*/
enum l2tp_ctrl_state {
  STATE_REINIT,
  STATE_RESOLVING,
  STATE_GET_USAGE,
  STATE_STANBDY,
  STATE_GET_COOKIE,
  STATE_GET_TUNNEL,
  STATE_KEEPALIVE,
  STATE_FAILED,
};

enum l2tp_session_features {
  FEATURE_UNIQUE_SESSION_ID  = 1 << 0,
  FEATURES_MASK = FEATURE_UNIQUE_SESSION_ID,
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
  // UUID.
  char *uuid;
  // Tunnel interface name.
  char *tunnel_iface;
  // Local tunnel identifer.
  unsigned int tunnel_id;
  // External hook script.
  char *hook;
  // Local IP endpoint.
  struct sockaddr_in local_endpoint;
  // Broker hostname.
  char *broker_hostname;
  // Broker port (or service name).
  char *broker_port;
  // Broker hostname resolution.
  asyncns_query_t *broker_resq;
  struct addrinfo broker_reshints;
  // Tunnel's UDP socket file descriptor.
  int fd;
  // Tunnel state.
  int state;
  // Broker usage.
  uint16_t usage;
  // Cookie.
  char cookie[8];
  // Netlink socket.
  struct nl_sock *nl_sock;
  int nl_family;
  // Sequence number for reliable messages.
  uint16_t reliable_seqno;
  // Sequence number for keep alive.
  uint32_t keepalive_seqno;
  // List of unacked reliable messages.
  reliable_message *reliable_unacked;
  // Force the tunnel to go over a certain interface.
  char *bind_iface;
  // Limits.
  uint32_t limit_bandwidth_down;
  // Tunnel uptime.
  time_t tunnel_up_since;

  // PMTU probing.
  int pmtu;
  int peer_pmtu;
  int probed_pmtu;
  time_t pmtu_reprobe_interval;
  time_t timer_pmtu_reprobe;
  time_t timer_pmtu_collect;
  time_t timer_pmtu_xmit;

  // Last keepalive and timers.
  time_t last_alive;
  time_t timer_usage;
  time_t timer_cookie;
  time_t timer_tunnel;
  time_t timer_keepalive;
  time_t timer_reinit;
  time_t timer_resolving;
} l2tp_context;

// Broker configuration.
typedef struct {
  char *address;
  char *port;
  l2tp_context *ctx;
  uint8_t broken;
} broker_cfg;

// Maximum number of brokers that can be handled in a single process.
#ifndef MAX_BROKERS
  #define MAX_BROKERS 10
#endif

// Forward declarations.
void context_delete_tunnel(l2tp_context *ctx);
void context_close_tunnel(l2tp_context *ctx, uint8_t reason);
int context_session_set_mtu(l2tp_context *ctx);
void context_send_packet(l2tp_context *ctx, uint8_t type, char *payload, uint8_t len);
void context_send_raw_packet(l2tp_context *ctx, char *packet, uint8_t len);
void context_send_reliable_packet(l2tp_context *ctx, uint8_t type, char *payload, uint8_t len);
int context_setup_tunnel(l2tp_context *ctx, uint32_t peer_tunnel_id, uint32_t server_features);
void context_free(l2tp_context *ctx);
void broker_select(broker_cfg *brokers, int broker_cnt);

static l2tp_context *main_context = NULL;
static asyncns_t *asyncns_context = NULL;

int broker_selector_usage(broker_cfg *brokers, int broker_cnt, int ready_cnt)
{
   // Select the available broker with the least usage and use it to establish a tunnel.
   int i = -1;
   int best = -1;
   for (i = 0; i < broker_cnt; i++) {
     if (brokers[i].ctx->state == STATE_STANBDY &&
         (best < 0 || brokers[i].ctx->usage < brokers[best].ctx->usage)) {
       best = i;
     }
   }

   return best;
}

int broker_selector_first_available(broker_cfg *brokers, int broker_cnt, int ready_cnt)
{
  // Select the first available broker and use it to establish a tunnel.
  int i;
  for (i = 0; i < broker_cnt; i++) {
    if (brokers[i].ctx->state == STATE_STANBDY) {
      return i;
    }
  }
  return -1;
}

int broker_selector_random(broker_cfg *brokers, int broker_cnt, int ready_cnt)
{
  // Select the r'th available broker and use it to establish a tunnel.
  int i;
  int r = rand() % ready_cnt;
  for (i = 0; i < broker_cnt; i++) {
    if (brokers[i].ctx->state == STATE_STANBDY && (r-- == 0)) {
      return i;
    }
  }
  return -1;
}

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

uint8_t parse_u8(char **buffer)
{
  uint8_t value = *((uint8_t*) *buffer);
  (*buffer) += sizeof(uint8_t);
  return value;
}

uint16_t parse_u16(char **buffer)
{
  uint16_t value = ntohs(*((uint16_t*) *buffer));
  (*buffer) += sizeof(uint16_t);
  return value;
}

uint32_t parse_u32(char **buffer)
{
  uint32_t value = ntohl(*((uint32_t*) *buffer));
  (*buffer) += sizeof(uint32_t);
  return value;
}

void put_u8(char **buffer, uint8_t value)
{
  (*buffer)[0] = value;
  (*buffer) += sizeof(value);
}

void put_u16(char **buffer, uint16_t value)
{
  (*buffer)[0] = value >> 8;
  (*buffer)[1] = value;
  (*buffer) += sizeof(value);
}

void put_u32(char **buffer, uint32_t value)
{
  (*buffer)[0] = value >> 24;
  (*buffer)[1] = value >> 16;
  (*buffer)[2] = value >> 8;
  (*buffer)[3] = value;
  (*buffer) += sizeof(value);
}

l2tp_context *context_new(char *uuid, const char *local_ip, const char *broker_hostname,
  char *broker_port, char *tunnel_iface, char *bind_iface, char *hook, int tunnel_id, int limit_bandwidth_down)
{
  l2tp_context *ctx = (l2tp_context*) calloc(1, sizeof(l2tp_context));
  if (!ctx) {
    syslog(LOG_ERR, "Failed to allocate memory for context!");
    return NULL;
  }

  ctx->state = STATE_REINIT;

  ctx->local_endpoint.sin_family = AF_INET;
  ctx->local_endpoint.sin_port = 0;
  if (inet_aton(local_ip, &ctx->local_endpoint.sin_addr) < 0) {
    syslog(LOG_ERR, "Failed to parse local endpoint!");
    goto free_and_return;
  }

  ctx->broker_hostname = strdup(broker_hostname);
  ctx->broker_port = strdup(broker_port);

  ctx->uuid = strdup(uuid);
  ctx->tunnel_iface = strdup(tunnel_iface);
  ctx->tunnel_id = tunnel_id;
  ctx->hook = hook ? strdup(hook) : NULL;

  ctx->bind_iface = bind_iface ? strdup(bind_iface) : NULL;

  // Reset limits.
  ctx->limit_bandwidth_down = (uint32_t) limit_bandwidth_down;

  // Setup the netlink socket.
  ctx->nl_sock = nl_socket_alloc();
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
  // We have to set this state here to be sure ctx is in a sane state when this functions fails(ret -1)
  // because other functions than the state machine call this function.
  ctx->state = STATE_REINIT;

  if (ctx->fd > 0)
    close(ctx->fd);
  ctx->fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (ctx->fd < 0)
    return -1;

  // Bind the socket to an interface if given.
  if (ctx->bind_iface) {
    int rc;

    rc = setsockopt(ctx->fd, SOL_SOCKET, SO_BINDTODEVICE, ctx->bind_iface, strlen(ctx->bind_iface) + 1);
    if (rc != 0) {
      syslog(LOG_ERR, "[%s:%s] Failed to bind to device!",
            ctx->broker_hostname, ctx->broker_port);
      return -1;
    }
  }

  if (bind(ctx->fd, (struct sockaddr*) &ctx->local_endpoint, sizeof(ctx->local_endpoint)) < 0) {
    syslog(LOG_ERR, "[%s:%s] Failed to bind to local endpoint - check WAN connectivity!",
            ctx->broker_hostname, ctx->broker_port);
    return -1;
  }

  int val = IP_PMTUDISC_PROBE;
  if (setsockopt(ctx->fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val)) < 0)
    return -1;

  ctx->keepalive_seqno = 0;
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
  ctx->usage = -1;

  // Reset relevant timers.
  time_t now = timer_now();
  ctx->timer_usage = 0;
  ctx->timer_cookie = 0;
  ctx->timer_tunnel = 0;
  ctx->timer_reinit = 0;
  ctx->timer_keepalive = now;
  ctx->timer_resolving = -1;

  // PMTU discovery.
  ctx->pmtu = 0;
  ctx->peer_pmtu = 0;
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
    syslog(LOG_ERR, "[%s:%s] Failed to start name resolution!",
            ctx->broker_hostname, ctx->broker_port);
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
  char *buf = buffer;

  put_u8(&buf, type);
  // Simple request are always a single 4 byte integer.
  put_u8(&buf, 4);
  put_u32(&buf, limit);

  // Now send the packet.
  context_send_reliable_packet(ctx, CONTROL_TYPE_LIMIT, (char*) &buffer, 6);
}

void context_setup_limits(l2tp_context *ctx)
{
  // Configure downstream bandwidth limit.
  if (ctx->limit_bandwidth_down > 0) {
    syslog(LOG_INFO, "[%s:%s] Requesting the broker to configure downstream bandwidth limit of %d kbps.",
      ctx->broker_hostname, ctx->broker_port, ctx->limit_bandwidth_down);
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

  // A valid package must at least 6 byte long.
  if (bytes < 6)
    return;

  // Decode packet header.
  char *buf = buffer;
  if (parse_u8(&buf) != 0x80 || parse_u16(&buf) != 0x73A7)
    return;

  // Check version number.
  if (parse_u8(&buf) != 1)
    return;

  uint8_t type = parse_u8(&buf);
  uint8_t payload_length = parse_u8(&buf);
  uint8_t error_code = 0;

  if (payload_length > (bytes - 6))
    return;

  // Each received packet counts as a liveness indicator.
  ctx->last_alive = timer_now();

  // Check packet type.
  switch (type) {
    case CONTROL_TYPE_USAGE: {
      if (ctx->state == STATE_GET_USAGE || ctx->state == STATE_STANBDY) {
        // Broker usage information.  We also received this in STATE_STANBY in case we first got
        // a COOKIE, but later also received a USAGE.
        ctx->usage = parse_u16(&buf);
        syslog(LOG_DEBUG, "[%s:%s] Broker usage: %u\n", ctx->broker_hostname, ctx->broker_port, ctx->usage);

        // Mark the connection as being available for later establishment.
        ctx->state = STATE_STANBDY;
      }
      break;
    }
    case CONTROL_TYPE_COOKIE: {
      if (ctx->state == STATE_GET_USAGE || ctx->state == STATE_GET_COOKIE) {
        if (payload_length != 8)
          break;

        memcpy(&ctx->cookie, buf, 8);

        if (ctx->state == STATE_GET_COOKIE) {
            // Proceed building a tunnel.
            ctx->state = STATE_GET_TUNNEL;
        } else {
            // State STATE_GET_USAGE.  We are ready.  Do not touch usage; the default is 0xFFFF and
            // we may even have also received some usage information.
            ctx->state = STATE_STANBDY;
        }
      }
      break;
    }
    case CONTROL_TYPE_ERROR: {
      if (payload_length > 0) {
        error_code = parse_u8(&buf);
      }
      if (ctx->state == STATE_GET_TUNNEL) {
        if (payload_length > 0)
          syslog(LOG_WARNING, "[%s:%s] Received error response from broker with errorcode %d!",
            ctx->broker_hostname, ctx->broker_port, error_code);
        else
          syslog(LOG_WARNING, "[%s:%s] Received error response from broker!",
            ctx->broker_hostname, ctx->broker_port);
        ctx->state = STATE_FAILED; // let the main loop restart everything
      } else if (ctx->state == STATE_KEEPALIVE) {
        if (payload_length > 0)
          syslog(LOG_ERR, "[%s:%s] Broker sent us a teardown request, closing tunnel with errorcode %d!",
            ctx->broker_hostname, ctx->broker_port, error_code);
        else
          syslog(LOG_ERR, "[%s:%s] Broker sent us a teardown request, closing tunnel!",
            ctx->broker_hostname, ctx->broker_port);
        context_close_tunnel(ctx, ERROR_REASON_OTHER_REQUEST);
      }
      break;
    }
    case CONTROL_TYPE_TUNNEL: {
      if (ctx->state == STATE_GET_TUNNEL) {
        if (payload_length < 4)
          break;

        uint32_t remote_tunnel_id = parse_u32(&buf);
        uint32_t server_features = 0;
        if (payload_length >= 8)
            server_features = parse_u32(&buf);

        if (context_setup_tunnel(ctx, remote_tunnel_id, server_features) < 0) {
          syslog(LOG_ERR, "[%s:%s] Unable to create local L2TP tunnel!",
            ctx->broker_hostname, ctx->broker_port);
          ctx->state = STATE_FAILED; // let the main loop restart everything
        } else {
          syslog(LOG_INFO, "[%s:%s] Tunnel successfully established.",
            ctx->broker_hostname, ctx->broker_port);
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
        // Send back an acknowledgement packet with proper size.
        char buffer[16];
        char *buf = buffer;
        put_u16(&buf, bytes);
        context_send_packet(ctx, CONTROL_TYPE_PMTUD_ACK, (char*) &buffer, 2);
      }
      break;
    }
    case CONTROL_TYPE_PMTUD_ACK: {
      if (ctx->state == STATE_KEEPALIVE) {
        if (payload_length != 2)
          break;
        // Process a PMTU probe.
        uint16_t psize = parse_u16(&buf) + IPV4_HDR_OVERHEAD;
        if (psize > ctx->probed_pmtu)
          ctx->probed_pmtu = psize;
      }
      break;
    }
    case CONTROL_TYPE_PMTU_NTFY: {
      if (ctx->state == STATE_KEEPALIVE) {
        if (payload_length != 2)
          break;

        // Process a peer PMTU notification message.
        uint16_t pmtu = parse_u16(&buf);
        if (pmtu != ctx->peer_pmtu) {
          ctx->peer_pmtu = pmtu;
          context_session_set_mtu(ctx);
        }
      }
      break;
    }
    case CONTROL_TYPE_REL_ACK: {
      if (payload_length != 2)
        break;

      // ACK of a reliable message.
      uint16_t seqno = parse_u16(&buf);
      reliable_message *msg = ctx->reliable_unacked;
      reliable_message *prev = NULL;
      while (msg != NULL) {
        if (msg->seqno == seqno) {
          // Remove from list.
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

void context_prepare_packet(l2tp_context *ctx, char *buf, uint8_t type, char *payload, uint8_t len)
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
  char *buf = buffer;

  put_u16(&buf, ctx->reliable_seqno);
  memcpy(buf, payload, len);
  context_prepare_packet(ctx, packet, type, (char*) &buffer, len + 2);

  // Store packet to unacked list.
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
        syslog(LOG_WARNING, "[%s:%s] Failed to send() control packet, interface disappeared?",
            ctx->broker_hostname, ctx->broker_port);
        syslog(LOG_WARNING, "[%s:%s] Forcing tunnel reinitialization.",
            ctx->broker_hostname, ctx->broker_port);
        ctx->state = STATE_FAILED;
        break;
      }
      default: {
        syslog(LOG_WARNING, "[%s:%s] Failed to send() control packet (errno=%d, type=%x)!",
            ctx->broker_hostname, ctx->broker_port, errno, packet[OFFSET_CONTROL_TYPE]);
        break;
      }
    }
  }
}

void context_send_packet(l2tp_context *ctx, uint8_t type, char *payload, uint8_t len)
{
  char buffer[2048];
  context_prepare_packet(ctx, &buffer[0], type, payload, len);

  // Pad the packet to 12 bytes to avoid it being filtered by some firewalls
  // when used over port 53.
  if (L2TP_CONTROL_SIZE + len < 12)
    len += 12 - L2TP_CONTROL_SIZE - len;

  // Send the packet
  context_send_raw_packet(ctx, (char*) &buffer, L2TP_CONTROL_SIZE + len);
}

void context_send_pmtu_probe(l2tp_context *ctx, size_t size)
{
  char buffer[2048] = {0,};
  if (size > 1500 || size < L2TP_CONTROL_SIZE)
    return;

  char *buf = buffer;
  put_u8(&buf, 0x80);
  put_u16(&buf, 0x73A7);
  put_u8(&buf, 1);
  put_u8(&buf, CONTROL_TYPE_PMTUD);
  put_u8(&buf, 0);

  // Send the packet.
  if (send(ctx->fd, &buffer, size - IPV4_HDR_OVERHEAD, 0) < 0) {
    switch (errno) {
      // Sometimes EAFNOSUPPORT is emitted for messages larger than the local MTU in case of PPPoE.
      case EAFNOSUPPORT:
      case EMSGSIZE: {
        // Message is larger than the local MTU. This is expected.
        break;
      }
      default: {
        syslog(LOG_WARNING, "[%s:%s] Failed to send() PMTU probe packet of size %zu (errno=%d)!",
          ctx->broker_hostname, ctx->broker_port, size, errno);
        break;
      }
    }
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
  char *buf = buffer;

  // First 8 bytes of payload is the cookie value.
  memcpy(buf, ctx->cookie, 8);
  buf += 8;

  // Then comes the size-prefixed UUID.
  size_t uuid_len = strlen(ctx->uuid);
  if (uuid_len > 255)
    uuid_len = 255;

  put_u8(&buf, uuid_len);
  memcpy(buf, ctx->uuid, uuid_len);
  buf += uuid_len;

  // And the local tunnel identifier.
  put_u32(&buf, ctx->tunnel_id);

  // And finally, our feature flags.
  put_u32(&buf, FEATURES_MASK);

  // Now send the packet.
  context_send_packet(ctx, CONTROL_TYPE_PREPARE, (char*) &buffer, (buf - &buffer[0]));
}

void context_send_usage_request(l2tp_context *ctx)
{
  char buffer[512];
  char *buf = buffer;

  // First, 8 bytes of padding.
  memcpy(buf, "UUUUUUUU", 8);
  buf += 8;

  // Then our feature flags.
  put_u32(&buf, FEATURES_MASK);

  // Now send the packet.
  context_send_packet(ctx, CONTROL_TYPE_USAGE, (char*) &buffer, (buf - &buffer[0]));
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
      syslog(LOG_WARNING, "[%s:%s] Failed to take down interface %s (errno=%d).",
        ctx->broker_hostname, ctx->broker_port, ifr.ifr_name, errno);
    }
  }

  // Delete the session.
  struct nl_msg *msg = nlmsg_alloc();
  genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->nl_family, 0, NLM_F_REQUEST,
    L2TP_CMD_SESSION_DELETE, L2TP_GENL_VERSION);

  nla_put_u32(msg, L2TP_ATTR_CONN_ID, ctx->tunnel_id);
  nla_put_u32(msg, L2TP_ATTR_SESSION_ID, 1);

  nl_send_auto_complete(ctx->nl_sock, msg);
  nlmsg_free(msg);
  nl_wait_for_ack(ctx->nl_sock);

  // Delete the tunnel.
  msg = nlmsg_alloc();
  genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->nl_family, 0, NLM_F_REQUEST,
    L2TP_CMD_TUNNEL_DELETE, L2TP_GENL_VERSION);

  nla_put_u32(msg, L2TP_ATTR_CONN_ID, ctx->tunnel_id);

  nl_send_auto_complete(ctx->nl_sock, msg);
  nlmsg_free(msg);
  nl_wait_for_ack(ctx->nl_sock);
}

int context_setup_tunnel(l2tp_context *ctx, uint32_t peer_tunnel_id, uint32_t server_features)
{
  // Create a tunnel.
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

  // Create a session (currently only a single session is supported).
  msg = nlmsg_alloc();
  genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->nl_family, 0, NLM_F_REQUEST,
    L2TP_CMD_SESSION_CREATE, L2TP_GENL_VERSION);

  nla_put_u32(msg, L2TP_ATTR_CONN_ID, ctx->tunnel_id);
  if (server_features & FEATURE_UNIQUE_SESSION_ID) {
    nla_put_u32(msg, L2TP_ATTR_SESSION_ID, ctx->tunnel_id);
    nla_put_u32(msg, L2TP_ATTR_PEER_SESSION_ID, peer_tunnel_id);
  } else {
    nla_put_u32(msg, L2TP_ATTR_SESSION_ID, 1);
    nla_put_u32(msg, L2TP_ATTR_PEER_SESSION_ID, 1);
  }
  nla_put_u16(msg, L2TP_ATTR_PW_TYPE, L2TP_PWTYPE_ETH);
  nla_put_string(msg, L2TP_ATTR_IFNAME, ctx->tunnel_iface);

  nl_send_auto_complete(ctx->nl_sock, msg);
  nlmsg_free(msg);

  result = nl_wait_for_ack(ctx->nl_sock);
  if (result < 0) {
    // Make sure we delete the tunnel again
    msg = nlmsg_alloc();
    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->nl_family, 0, NLM_F_REQUEST,
      L2TP_CMD_TUNNEL_DELETE, L2TP_GENL_VERSION);

    nla_put_u32(msg, L2TP_ATTR_CONN_ID, ctx->tunnel_id);

    nl_send_auto_complete(ctx->nl_sock, msg);
    nlmsg_free(msg);
    nl_wait_for_ack(ctx->nl_sock);

    return -1;
  }

  return 0;
}

int context_session_set_mtu(l2tp_context *ctx)
{
  if (ctx->pmtu == 0 && ctx->peer_pmtu == 0)
    return 0;
  uint16_t mtu = 0xFFFF;
  if (ctx->pmtu > 0)
    mtu = ctx->pmtu - L2TP_TUN_OVERHEAD;
  if (ctx->peer_pmtu > 0 && ctx->peer_pmtu < mtu)
    mtu = ctx->peer_pmtu;
  syslog(LOG_INFO, "[%s:%s] Setting MTU to %d", ctx->broker_hostname, ctx->broker_port, (int) mtu);

  // Update the device MTU.
  struct ifreq ifr;

  if (mtu < 1280)
    mtu = 1280;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, ctx->tunnel_iface, sizeof(ifr.ifr_name));
  ifr.ifr_mtu = mtu;
  if (ioctl(ctx->fd, SIOCSIFMTU, &ifr) < 0) {
    syslog(LOG_WARNING, "[%s:%s] Failed to set MTU to %d on device %s (errno=%d)!",
      ctx->broker_hostname, ctx->broker_port, (int) mtu,  ifr.ifr_name, errno);
    return -1;
  }

  // Update session parameters.
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

void context_close_tunnel(l2tp_context *ctx, uint8_t reason)
{
  reason |= ERROR_DIRECTION_CLIENT;

  // Notify the broker that the tunnel has been closed.
  context_send_packet(ctx, CONTROL_TYPE_ERROR, (char *) &reason, 1);

  // Call down hook, delete the tunnel and let the main loop restart everything.
  context_call_hook(ctx, "session.down");
  context_delete_tunnel(ctx);
  ctx->state = STATE_FAILED;
}

void broker_select(broker_cfg *brokers, int broker_cnt)
{
  // Poll the file descriptor to see if anything is to be read/written.
  fd_set rfds;
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;

  FD_ZERO(&rfds);

  // Add descriptor for DNS resolution.
  int nsfd = asyncns_fd(asyncns_context);
  int nfds = nsfd;
  FD_SET(nsfd, &rfds);

  int i;
  for (i = 0; i < broker_cnt; i++) {
    l2tp_context *ctx = brokers[i].ctx;
    FD_SET(ctx->fd, &rfds);
    nfds = nfds > ctx->fd ? nfds : ctx->fd;
  }

  int res = select(nfds + 1, &rfds, NULL, NULL, &tv);
  if (res == -1) {
    return;
  } else if (res) {
    for (i = 0; i < broker_cnt; i++) {
      l2tp_context *ctx = brokers[i].ctx;
      if (FD_ISSET(ctx->fd, &rfds))
        context_process_control_packet(ctx);
    }
    if (FD_ISSET(nsfd, &rfds))
      asyncns_wait(asyncns_context, 0);
  }
}

void context_process(l2tp_context *ctx)
{
  // Transmit packets if needed.
  switch (ctx->state) {
    case STATE_REINIT: {
      if (is_timeout(&ctx->timer_reinit, 2)) {
        syslog(LOG_INFO, "[%s:%s] Reinitializing tunnel context.",
          ctx->broker_hostname, ctx->broker_port);
        if (context_reinitialize(ctx) < 0) {
          syslog(LOG_ERR, "[%s:%s] Unable to reinitialize the context!",
            ctx->broker_hostname, ctx->broker_port);
        }
      }
      if (ctx->state != STATE_RESOLVING)
        break;
      // Deliberate fall-through to STATE_RESOLVING
    }
    case STATE_RESOLVING: {
      if (ctx->broker_resq == NULL)
        context_start_connect(ctx);

      // Check if address has already been resolved and change state.
      if (ctx->broker_resq && asyncns_isdone(asyncns_context, ctx->broker_resq)) {
        struct addrinfo *result;
        int status = asyncns_getaddrinfo_done(asyncns_context, ctx->broker_resq, &result);

        if (status != 0) {
          syslog(LOG_ERR, "[%s:%s] Failed to resolve hostname.",
            ctx->broker_hostname, ctx->broker_port);
          /* TODO: memory leak - asyncns_getaddrinfo_done() does not free in all error cases ctx->broker_resp.
           * Fix asyncns - remove free() from asyncns_getaddrinfo_done()
           */
          ctx->broker_resq = NULL;
          ctx->state = STATE_REINIT;
          return;
        } else {
          if (connect(ctx->fd, result->ai_addr, result->ai_addrlen) < 0) {
            syslog(LOG_ERR, "[%s:%s] Failed to connect to remote endpoint - check WAN connectivity!",
              ctx->broker_hostname, ctx->broker_port);
            ctx->state = STATE_REINIT;
          } else {
            ctx->state = STATE_GET_USAGE;
          }
          asyncns_freeaddrinfo(result);
          ctx->broker_resq = NULL;
        }
      } else if (is_timeout(&ctx->timer_resolving, 2)) {
        syslog(LOG_ERR, "[%s:%s] Hostname resolution timed out.",
          ctx->broker_hostname, ctx->broker_port);

        if (ctx->broker_resq)
          asyncns_cancel(asyncns_context, ctx->broker_resq);
        ctx->broker_resq = NULL;
        ctx->state = STATE_REINIT;
        return;
      }
      if (ctx->state == STATE_GET_USAGE) {
        // Deliberate fall-through, let's get the usage ASAP.
      } else {
        break;
      }
    }
    case STATE_GET_USAGE: {
      if (ctx->timer_usage == 0) {
        // The initial request.  We only ask for usage.
        context_send_usage_request(ctx);
        ctx->timer_usage = timer_now();
      } else if (is_timeout(&ctx->timer_usage, 2)) {
        // *Not* the initial request.  Also ask for cookie, to provide compatibility with old brokers.
        context_send_usage_request(ctx);
        context_send_packet(ctx, CONTROL_TYPE_COOKIE, "XXXXXXXX", 8);
      }
      break;
    }
    case STATE_GET_COOKIE: {
      // Send request for a tasty cookie.
      if (is_timeout(&ctx->timer_cookie, 2))
        context_send_packet(ctx, CONTROL_TYPE_COOKIE, "XXXXXXXX", 8);
      break;
    }
    case STATE_GET_TUNNEL: {
      // Send tunnel setup request.
      if (is_timeout(&ctx->timer_tunnel, 2))
        context_send_setup_request(ctx);
      break;
    }
    case STATE_KEEPALIVE: {
      // Send periodic keepalive messages.
      // The sequence number is needed because some ISP (usually cable or mobile operators)
      // do some "optimisation" and drop udp packets containing the same content.
      if (is_timeout(&ctx->timer_keepalive, 5)) {
        char buffer[4];
        char *buf = buffer;
        put_u32(&buf, ctx->keepalive_seqno);
        context_send_packet(ctx, CONTROL_TYPE_KEEPALIVE, buffer, 4);
        ctx->keepalive_seqno++;
      }

      // Send periodic PMTU probes.
      if (is_timeout(&ctx->timer_pmtu_reprobe, ctx->pmtu_reprobe_interval)) {
        ctx->probed_pmtu = 0;
        ctx->timer_pmtu_collect = timer_now();
        ctx->timer_pmtu_xmit = timer_now();
        context_pmtu_start_discovery(ctx);
        ctx->pmtu_reprobe_interval *= 2;
        if (ctx->pmtu_reprobe_interval > 600)
          ctx->pmtu_reprobe_interval = 600;
      }

      // Check if we need to collect PMTU probes.
      if (is_timeout(&ctx->timer_pmtu_collect, 5)) {
        if (ctx->probed_pmtu > 0 && ctx->probed_pmtu != ctx->pmtu) {
          ctx->pmtu = ctx->probed_pmtu;
          context_session_set_mtu(ctx);
        }
        if (ctx->pmtu > 0) {
          // Notify the broker of the configured MTU.
          char buffer[16];
          char *buf = buffer;
          put_u16(&buf, ctx->pmtu - L2TP_TUN_OVERHEAD);
          context_send_packet(ctx, CONTROL_TYPE_PMTU_NTFY, (char*) &buffer, 2);
        }
        ctx->probed_pmtu = 0;
        ctx->timer_pmtu_collect = -1;
        ctx->timer_pmtu_xmit = -1;
      }

      if (is_timeout(&ctx->timer_pmtu_xmit, 1))
        context_pmtu_start_discovery(ctx);

      // Check if we need to attempt to retransmit any reliable messages.
      reliable_message *msg = ctx->reliable_unacked;
      reliable_message *prev = NULL;
      while (msg != NULL) {
        if (is_timeout(&msg->timer_rexmit, 1)) {
          if (++msg->retries >= 10) {
            syslog(LOG_WARNING, "[%s:%s] Dropping message that has been retried too many times.",
              ctx->broker_hostname, ctx->broker_port);

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

      // Check if the tunnel is still alive.
      if (timer_now() - ctx->last_alive > 60) {
        syslog(LOG_WARNING, "[%s:%s] Tunnel has timed out, closing down interface.",
            ctx->broker_hostname, ctx->broker_port);
        context_close_tunnel(ctx, ERROR_REASON_TIMEOUT);
      }
      break;
    }
    case STATE_STANBDY:
    case STATE_FAILED: {
      break;
    }
  }
}

void cleanup()
{
  if (main_context) {
    context_close_tunnel(main_context, ERROR_REASON_SHUTDOWN);
    context_free(main_context);
    main_context = NULL;
  }

  if (asyncns_context)
    asyncns_free(asyncns_context);
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
  free(ctx->bind_iface);
  free(ctx);
}



void term_handler(int signum)
{
  (void) signum; // Unused.

  syslog(LOG_WARNING, "Got termination signal, shutting down tunnel...");

  cleanup();
  exit(1);
}

void child_handler(int signum)
{
  (void) signum; // Unused.

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
    "       -a            select broker based on use\n"
    "       -g            select first available broker to connect to (default)\n"
    "       -r            select a random broker\n"
  );
}

int main(int argc, char **argv)
{
  // Install signal handlers.
  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, term_handler);
  signal(SIGTERM, term_handler);
  signal(SIGCHLD, child_handler);

  // Parse program options.
  int log_option = 0;
  char *uuid = NULL, *local_ip = "0.0.0.0", *tunnel_iface = NULL, *bind_iface_opt = NULL;
  char *hook = NULL;
  unsigned int tunnel_id = 1;
  int limit_bandwidth_down = 0;

  broker_cfg brokers[MAX_BROKERS];
  int (*select_broker)(broker_cfg *, int, int) = broker_selector_first_available;
  int broker_cnt = 0;

  int c;
  while ((c = getopt(argc, argv, "hfu:l:b:p:i:s:t:L:I:agr")) != -1) {
    switch (c) {
      case 'h': {
        show_help(argv[0]);
        return 1;
      }
      case 'a': select_broker = broker_selector_usage; break;
      case 'g': select_broker = broker_selector_first_available; break;
      case 'r': select_broker = broker_selector_random; break;

      case 'f': log_option |= LOG_PERROR; break;
      case 'u': uuid = strdup(optarg); break;
      case 'l': local_ip = strdup(optarg); break;
      case 'b': {
        if (broker_cnt >= MAX_BROKERS) {
          fprintf(stderr, "ERROR: You cannot specify more than %d brokers!\n", MAX_BROKERS);
          return 1;
        }

        char *pos = strchr(optarg, ':');
        if (!pos) {
          fprintf(stderr, "ERROR: Each broker must be passed in the format 'host:port'!\n");
          return 1;
        }

        brokers[broker_cnt].address = strndup(optarg, pos - optarg);
        brokers[broker_cnt].port = strdup(pos + 1);
        brokers[broker_cnt].ctx = NULL;
        brokers[broker_cnt].broken = 0;
        broker_cnt++;
        break;
      }
      case 'i': tunnel_iface = strdup(optarg); break;
      case 's': hook = strdup(optarg); break;
      case 't': tunnel_id = strtoul(optarg, NULL, 0); break;
      case 'L': limit_bandwidth_down = atoi(optarg); break;
      case 'I': bind_iface_opt = strdup(optarg); break;
      default: {
        fprintf(stderr, "ERROR: Invalid option %c!\n", c);
        show_help(argv[0]);
        return 1;
      }
    }
  }

  // Check for root permissions.
  if (getuid() != 0) {
    fprintf(stderr, "ERROR: Root access is required to setup tunnels!\n");
    return 1;
  }

  if (!uuid || broker_cnt < 1 || !tunnel_iface) {
    fprintf(stderr, "ERROR: UUID, tunnel interface and broker list are required options!\n");
    show_help(argv[0]);
    return 1;
  }

  // Open the syslog facility.
  openlog("td-client", log_option, LOG_DAEMON);

  // Initialize the async DNS resolver.
  if (!(asyncns_context = asyncns_new(2))) {
    syslog(LOG_ERR, "Unable to initialize DNS resolver!");
    return 1;
  }

  // Initialize contexts for all configured brokers in standby mode.
  int i;
  for (i = 0; i < broker_cnt; i++) {
    // Attempt to initialize the L2TP context. This might fail because the network is still
    // unreachable or if the L2TP kernel modules are not loaded. We will retry for 5 minutes
    // and then abort.
    for (;;) {
      brokers[i].ctx = context_new(uuid, local_ip, brokers[i].address, brokers[i].port,
        tunnel_iface, bind_iface_opt, hook, tunnel_id, limit_bandwidth_down);

      if (!brokers[i].ctx) {
        syslog(LOG_ERR, "[%s:%s] Unable to initialize tunneldigger context! Retrying in 5 seconds...",
            brokers[i].address, brokers[i].port);
        sleep(5);
        continue;
      }

      // Context successfully initialized.
      break;
    }
  }

  for (;;) {
    int working_brokers = 0;
    // Make sure all brokers are in sane state.
    for (i = 0; i < broker_cnt; i++) {
      context_reinitialize(brokers[i].ctx);
      if (brokers[i].broken && brokers[i].broken + 3600 < timer_now()) {
        // This one broke more than an hour ago, give it another chance.
        brokers[i].broken = 0;
      }
      if (!brokers[i].broken)
        working_brokers += 1;
    }

    syslog(LOG_INFO, "Performing broker selection...");

    // Reset availability information and standby setting.
    for (i = 0; i < broker_cnt; i++) {
      if (brokers[i].broken) {
        // Inhibit hostname resolution and connect process.
        syslog(LOG_INFO, "[%s:%s] Not trying broker again as it broke last time we tried.",
          brokers[i].address, brokers[i].port);
        brokers[i].ctx->state = STATE_FAILED;
      }
    }

    // Perform broker processing for 10 seconds or until all brokers are ready
    // (whichever is shorter); since all contexts are in standby mode, all
    // available connections will be stuck in GET_COOKIE state.
    time_t timer_collect = timer_now();
    int ready_cnt = 0;
    for (;;) {
      ready_cnt = 0;
      broker_select(brokers, broker_cnt); // poll from all FDs
      for (i = 0; i < broker_cnt; i++) {
        context_process(brokers[i].ctx);
      }

      for (i = 0; i < broker_cnt; i++) {
        ready_cnt += brokers[i].ctx->state == STATE_STANBDY ? 1 : 0;
      }

      if (ready_cnt == working_brokers || is_timeout(&timer_collect, 10))
        break;

      // First available broker just use the first one available.
      if (select_broker == broker_selector_first_available && ready_cnt > 0)
        break;
    }

    i = select_broker(brokers, broker_cnt, ready_cnt);
    if (i == -1) {
      syslog(LOG_ERR, "No suitable brokers found. Retrying in 5 seconds");
      sleep(5);
      // Un-break all brokers.  There is no point in avoiding bad brokers if that means
      // we have no candidates left.
      for (i = 0; i < broker_cnt; i++) {
        brokers[i].broken = 0;
      }
      continue;
    }

    // Henceforth, brokers[i] is the active broker.
    main_context = brokers[i].ctx;
    syslog(LOG_INFO, "Selected %s:%s as the best broker.", brokers[i].address,
      brokers[i].port);

    // Activate the broker.
    main_context->state = STATE_GET_COOKIE;

    // Initially, we mark this broker as broken.  We will remove this mark after establishing
    // a connection.  We only want to consider a broker as broker if the initial connection fails;
    // disconnecting later (e.g. because the broker got restarted) is fine.
    brokers[i].broken = timer_now();

    // Perform processing on the main context; if the connection fails and does
    // not recover after 15 seconds, restart the broker selection process.
    time_t timer_establish = timer_now();
    for (;;) {
      broker_select(&brokers[i], 1); // poll from this FD
      context_process(main_context);

      if (main_context->state == STATE_FAILED) {
        syslog(LOG_ERR, "[%s:%s] Connection lost.",
          main_context->broker_hostname, main_context->broker_port);
        break;
      }

      // If the connection is lost, we start the reconnection timer.
      // Hitting this code path should not be possible:  Once we are in STATE_KEEPALIVE
      // (which is a prerequisite for ever having `timer_establish < 0`),
      // the only possible transition is to STATE_FAILED.  But let's play safe.
      if (timer_establish < 0 && main_context->state != STATE_KEEPALIVE) {
        timer_establish = timer_now();
      }

      // After 15 seconds, we check if the tunnel has been established.
      if (is_timeout(&timer_establish, 15)) {
        if (main_context->state != STATE_KEEPALIVE) {
          // Tunnel is not established yet, skip to the next broker.
          syslog(LOG_ERR, "[%s:%s] Connection not established after 15 seconds, restarting broker selection...",
            main_context->broker_hostname, main_context->broker_port);
          break;
        }

        // We successfully established a connection, this broker is fine.
        brokers[i].broken = 0;

        timer_establish = -1;
      }
    }

    // If we are here, the connection has been lost.
    main_context = NULL;
  }

  cleanup();

  return 0;
}
