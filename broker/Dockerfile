FROM ubuntu

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
        ebtables python-virtualenv wget && \
    mkdir -p /srv/tunneldigger/tunneldigger/broker && \
    cd /srv/tunneldigger && \
    virtualenv env_tunneldigger
    
#
# Install Tunneldigger
#
#
COPY . /srv/tunneldigger/tunneldigger/broker
RUN cd /srv/tunneldigger/tunneldigger/broker && \
    . /srv/tunneldigger/env_tunneldigger/bin/activate && \
    python setup.py install

CMD docker/start.sh


