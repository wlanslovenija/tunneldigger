import ConfigParser
import logging
import logging.config
import os
import select
import socket
import sys

from . import broker

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
pollables = {}
poller = select.epoll()

# Initialize the tunnel manager.
tunnel_manager = broker.TunnelManager(
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

    broker_instance.register(poller, pollables)
    brokers.append(broker_instance)

logger.info("Broker initialized.")

try:
    # Start the main event loop.
    while True:
        for fd, event in poller.poll():
            pollable = pollables.get(fd, None)
            if not pollable:
                continue

            if event & select.EPOLLIN:
                pollable.read()
except KeyboardInterrupt:
    pass
finally:
    logger.info("Shutting down tunneldigger broker.")

    # Shutdown all brokers and tunnels.
    for broker_instance in brokers:
        broker_instance.close()
    tunnel_manager.close()