FROM hwdsl2/ipsec-vpn-server

#
# Get Tunneldigger files
#
RUN mkdir -p /srv/tunneldigger/tunneldigger/broker
COPY setup.py /srv/tunneldigger/tunneldigger/broker
COPY contrib /srv/tunneldigger/tunneldigger/broker/contrib
COPY scripts /srv/tunneldigger/tunneldigger/broker/scripts
COPY src /srv/tunneldigger/tunneldigger/broker/src

#
# Installation as described in the server documentation
# https://tunneldigger.readthedocs.io/en/latest/server.html
#
# Using the recommended apt practices.
# https://docs.docker.com/develop/develop-images/dockerfile_best-practices/
#
RUN apt-get update && \
    apt-get install -y \
        iproute2 bridge-utils libnetfilter-conntrack-dev \
        libnfnetlink-dev libffi-dev python-dev libevent-dev \
        ebtables python-virtualenv wget gcc && \
    cd /srv/tunneldigger && \
    virtualenv env_tunneldigger && \
    cd /srv/tunneldigger/tunneldigger/broker && \
    . /srv/tunneldigger/env_tunneldigger/bin/activate && \
    python setup.py install && \
    apt-get -y purge gcc && \
    apt-get -y autoremove

#
# Get all files for docker
#
COPY docker /srv/tunneldigger/tunneldigger/broker/docker

#
# Start the service
#
CMD /srv/tunneldigger/tunneldigger/broker/docker/start.sh


