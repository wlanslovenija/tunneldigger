/*
 * Client for our custom L2TPv3 brokerage protocol.
 *
 * Copyright (C) 2012 by Jernej Kos <k@jst.sm>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>
#include <netlink/genl/ctrl.h>
#include <netlink/utils.h>

#include <linux/genetlink.h>
#include <linux/l2tp.h>

#define L2TP_CONTROL_SIZE 6

#ifdef LIBNL_TINY
#define nl_handle nl_sock
#define nl_handle_alloc nl_socket_alloc
#endif

enum l2tp_ctrl_type {
  CONTROL_TYPE_COOKIE    = 0x01,
  CONTROL_TYPE_PREPARE   = 0x02,
  CONTROL_TYPE_ERROR     = 0x03,
  CONTROL_TYPE_TUNNEL    = 0x04,
  CONTROL_TYPE_KEEPALIVE = 0x05,
};

enum l2tp_ctrl_state {
  STATE_GET_COOKIE,
  STATE_GET_TUNNEL,
  STATE_KEEPALIVE,
  STATE_REINIT,
};

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
  // Broker IP endpoint
  struct sockaddr_in broker_endpoint;
  // Tunnel's UDP socket file descriptor
  int fd;
  // Tunnel state
  int state;
  // Cookie
  char cookie[8];
  // Netlink socket
  struct nl_handle *nl_sock;
  int nl_family;
  
  // Last keepalive and timers
  time_t last_alive;
  time_t timer_cookie;
  time_t timer_tunnel;
  time_t timer_keepalive;
  time_t timer_reinit;
} l2tp_context;

// Forward declarations
void context_close_tunnel(l2tp_context *ctx);

static l2tp_context *main_context = NULL;

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

l2tp_context *context_init(char *uuid, const char *local_ip, const char *broker_ip,
  int broker_port, char *tunnel_iface, int tunnel_id)
{
  l2tp_context *ctx = (l2tp_context*) malloc(sizeof(l2tp_context));
  if (!ctx) {
    return NULL;
  }
  
  ctx->state = STATE_GET_COOKIE;
  
  // Setup the UDP socket that we will use for connecting with the
  // broker and for data transport
  ctx->fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (ctx->fd < 0)
    goto free_and_return;
  
  ctx->local_endpoint.sin_family = AF_INET;
  ctx->local_endpoint.sin_port = 0;
  if (inet_aton(local_ip, &ctx->local_endpoint.sin_addr.s_addr) < 0)
    goto free_and_return;
  
  ctx->broker_endpoint.sin_family = AF_INET;
  ctx->broker_endpoint.sin_port = htons(broker_port);
  if (inet_aton(broker_ip, &ctx->broker_endpoint.sin_addr.s_addr) < 0)
    goto free_and_return;
  
  if (bind(ctx->fd, (struct sockaddr*) &ctx->local_endpoint, sizeof(ctx->local_endpoint)) < 0)
    goto free_and_return;
  
  if (connect(ctx->fd, (struct sockaddr*) &ctx->broker_endpoint, sizeof(ctx->broker_endpoint)) < 0)
    goto free_and_return;
  
  ctx->uuid = uuid;
  ctx->tunnel_iface = tunnel_iface;
  ctx->tunnel_id = tunnel_id;
  ctx->hook = NULL;
  
  // Reset all timers
  time_t now = timer_now();
  ctx->last_alive = now;
  ctx->timer_cookie = now;
  ctx->timer_tunnel = now;
  ctx->timer_keepalive = now;
  ctx->timer_reinit = now;
  
  // Setup the netlink socket
  ctx->nl_sock = nl_handle_alloc();
  if (!ctx->nl_sock)
    goto free_and_return;
  
  if (nl_connect(ctx->nl_sock, NETLINK_GENERIC) < 0)
    goto free_and_return;
  
  ctx->nl_family = genl_ctrl_resolve(ctx->nl_sock, L2TP_GENL_NAME);
  if (ctx->nl_family < 0)
    goto free_and_return;
  
  return ctx;
free_and_return:
  free(ctx);
  return NULL;
}

int context_reinitialize(l2tp_context *ctx)
{
  close(ctx->fd);
  ctx->fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (ctx->fd < 0)
    return -1;
  
  if (bind(ctx->fd, (struct sockaddr*) &ctx->local_endpoint, sizeof(ctx->local_endpoint)) < 0)
    return -1;
  
  if (connect(ctx->fd, (struct sockaddr*) &ctx->broker_endpoint, sizeof(ctx->broker_endpoint)) < 0)
    return -1;
  
  // Reset relevant timers
  time_t now = timer_now();
  ctx->timer_cookie = now;
  ctx->timer_tunnel = now;
  ctx->timer_keepalive = now;
  ctx->timer_reinit = now;
  
  return 0;
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

void context_process_control_packet(l2tp_context *ctx)
{
  char buffer[1024];
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
          ctx->state = STATE_KEEPALIVE;
        }
      }
      break;
    }
    case CONTROL_TYPE_KEEPALIVE: break;
    default: return;
  }
}

void context_send_packet(l2tp_context *ctx, uint8_t type, char *payload, uint8_t len)
{
  char buffer[1024];
  unsigned char *buf = (unsigned char*) &buffer;
  put_u8(&buf, 0x80);
  put_u16(&buf, 0x73A7);
  put_u8(&buf, 1);
  put_u8(&buf, type);
  put_u8(&buf, len);
  if (payload)
    memcpy(buf, payload, len);
  
  // Send the packet
  if (send(ctx->fd, &buffer, L2TP_CONTROL_SIZE + len, 0) < 0) {
    syslog(LOG_WARNING, "Failed to send() control packet (errno=%d)!", errno);
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

int context_delete_tunnel(l2tp_context *ctx)
{
  // Delete the session
  struct nl_msg *msg = nlmsg_alloc();
  genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->nl_family, 0, NLM_F_REQUEST,
    L2TP_CMD_SESSION_DELETE, L2TP_GENL_VERSION);
  
  nla_put_u32(msg, L2TP_ATTR_CONN_ID, 1);
  nla_put_u32(msg, L2TP_ATTR_SESSION_ID, 1);
  
  nl_send_auto_complete(ctx->nl_sock, msg);
  nlmsg_free(msg);
  nl_wait_for_ack(ctx->nl_sock);
  
  // Delete the tunnel
  msg = nlmsg_alloc();
  genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, ctx->nl_family, 0, NLM_F_REQUEST,
    L2TP_CMD_TUNNEL_DELETE, L2TP_GENL_VERSION);
  
  nla_put_u32(msg, L2TP_ATTR_CONN_ID, 1);
  
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
  
  int res = select(ctx->fd + 1, &rfds, NULL, NULL, &tv);
  if (res == -1)
    return;
  else if (res)
    context_process_control_packet(ctx);
  
  // Transmit packets if needed
  switch (ctx->state) {
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
      
      // Check if the tunnel is still alive
      if (timer_now() - ctx->last_alive > 30) {
        syslog(LOG_WARNING, "Tunnel has timed out, closing down interface.");
        context_close_tunnel(ctx);
      }
      break;
    }
    case STATE_REINIT: {
      if (is_timeout(&ctx->timer_reinit, 60)) {
        syslog(LOG_INFO, "Reinitializing tunnel context.");
        if (context_reinitialize(ctx) < 0) {
          syslog(LOG_ERR, "Unable to reinitialize the context!");
        } else {
          ctx->state = STATE_GET_COOKIE;
        }
      }
      break;
    }
  }
}

void context_free(l2tp_context *ctx)
{
  free(ctx->uuid);
  free(ctx->tunnel_iface);
  free(ctx->hook);
  free(ctx);
}

void term_handler(int signum)
{
  if (main_context) {
    context_close_tunnel(main_context);
    main_context = NULL;
  }
  
  exit(1);
}

void child_handler(int signum)
{
  int status;
  waitpid(-1, &status, WNOHANG);
}

void show_help(const char *app)
{
  fprintf(stderr, "usage: %s [options]\n", app);
  fprintf(stderr,
    "       -h         this text\n"
    "       -f         don't daemonize into background\n"
    "       -u uuid    set UUID string\n"
    "       -l ip      local IP address to bind to\n"
    "       -b ip      broker IP address\n"
    "       -p port    broker port (default 53)\n"
    "       -i iface   tunnel interface name\n"
    "       -s hook    hook script\n"
    "       -t id      local tunnel id (default 1)\n"
  );
}

int main(int argc, char **argv)
{
  // Check for root permissions
  if (getuid() != 0) {
    fprintf(stderr, "ERROR: Root access is required to setup tunnels!\n");
    return 1;
  }
  
  // Open the syslog facility
  openlog("l2tp-client", 0, LOG_DAEMON);
  
  // Install signal handlers
  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, term_handler);
  signal(SIGTERM, term_handler);
  signal(SIGCHLD, child_handler);
  
  // Parse program options
  char *uuid = NULL, *local_ip = NULL, *broker_ip = NULL, *tunnel_iface = NULL;
  char *hook = NULL;
  int broker_port = 53;
  int tunnel_id = 1;
  char c;
  while ((c = getopt(argc, argv, "hfu:l:b:p:i:s:t:")) != EOF) {
    switch (c) {
      case 'h': {
        show_help(argv[0]);
        return 1;
      }
      case 'f': break;
      case 'u': uuid = strdup(optarg); break;
      case 'l': local_ip = strdup(optarg); break;
      case 'b': broker_ip = strdup(optarg); break;
      case 'p': broker_port = atoi(optarg); break;
      case 'i': tunnel_iface = strdup(optarg); break;
      case 's': hook = strdup(optarg); break;
      case 't': tunnel_id = atoi(optarg); break;
      default: {
        fprintf(stderr, "ERROR: Invalid option %c!\n", c);
        show_help(argv[0]);
        return 1;
      }
    }
  }
  
  if (!uuid || !local_ip || !broker_ip || !tunnel_iface) {
    fprintf(stderr, "ERROR: UUID, local IP, broker IP and tunnel interface are required options!\n");
    show_help(argv[0]);
    return 1;
  }
  
  main_context = context_init(uuid, local_ip, broker_ip, broker_port, tunnel_iface, tunnel_id);
  main_context->hook = hook;
  if (!main_context) {
    fprintf(stderr, "ERROR: Unable to initialize L2TP context!\n");
    return 1;
  }
  
  for (;;) {
    context_process(main_context);
  }
  
  return 0;
}

