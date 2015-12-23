import ConfigParser
import logging
import logging.config
import os
import socket
import sys

from . import broker, eventloop, hooks

if os.getuid() != 0:
    print "ERROR: The tunneldigger broker must be run as root."
    sys.exit(1)

# Load configuration.
config = ConfigParser.SafeConfigParser()
try:
    config.read(sys.argv[1])
except IOError:
    print "ERROR: Failed to open the specified configuration file '%s'!" % sys.argv[1]
    sys.exit(1)
except IndexError:
    print "ERROR: First argument must be a configuration file path!"
    sys.exit(1)

# Configure logging.
# TODO: Make logging externally configurable.
LOGGING_CONFIGURATION = {
    'version': 1,
    'formatters': {
        'simple': {
            'format': '[%(levelname)s/%(name)s] %(message)s',
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'loggers': {
        'tunneldigger': {
            'handlers': ['console'],
            'level': 'INFO',
        }
    }
}
logging.config.dictConfig(LOGGING_CONFIGURATION)

# Logger.
logger = logging.getLogger("tunneldigger.broker")
logger.info("Initializing the tunneldigger broker.")

# Initialize the event loop.
event_loop = eventloop.EventLoop()

# Initialize the hook manager.
hook_manager = hooks.HookManager(event_loop)
for hook in ('session.up', 'session.pre-down', 'session.down', 'session.mtu-changed'):
    try:
        script = config.get('hooks', hook).strip()
        if not script:
            continue
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
        continue

    hook_manager.register_hook(hook, script)
    logger.info("Registered script '%s' for hook '%s'." % (script, hook))

# Initialize the tunnel manager.
tunnel_manager = broker.TunnelManager(
    hook_manager=hook_manager,
    max_tunnels=config.getint('broker', 'max_tunnels'),
    tunnel_id_base=config.getint('broker', 'tunnel_id_base'),
    tunnel_port_base=config.getint('broker', 'port_base'),
    namespace=config.get('broker', 'namespace'),
)
tunnel_manager.initialize()

logger.info("Maximum number of tunnels is %d." % tunnel_manager.max_tunnels)
logger.info("Tunnel identifier base is %d." % tunnel_manager.tunnel_id_base)
logger.info("Tunnel port base is %d." % tunnel_manager.tunnel_port_base)
logger.info("Namespace is %s." % tunnel_manager.namespace)

# Initialize one broker for each port.
brokers = []
broker_host = config.get('broker', 'address')
for port in config.get('broker', 'port').split(','):
    try:
        broker_instance = broker.Broker(
            (broker_host, int(port)),
            config.get('broker', 'interface'),
            tunnel_manager,
        )
        logger.info("Listening on %s:%d." % broker_instance.address)
    except ValueError:
        logger.warning("Malformed port number '%s', skipping." % port)
        continue
    except socket.error:
        # Skip ports that we fail to listen on.
        logger.warning("Failed to listen on %s:%s, skipping." % (broker_host, port))
        continue

    broker_instance.register(event_loop)
    brokers.append(broker_instance)

logger.info("Broker initialized.")

try:
    # Start the main event loop.
    event_loop.start()
except KeyboardInterrupt:
    pass
finally:
    logger.info("Shutting down tunneldigger broker.")

    # Shutdown all brokers and tunnels.
    for broker_instance in brokers:
        broker_instance.close()
    tunnel_manager.close()
