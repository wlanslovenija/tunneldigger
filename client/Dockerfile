FROM ubuntu

RUN mkdir -p /srv/tunneldigger/client/

COPY CMakeLists.txt /srv/tunneldigger/client/CMakeLists.txt
COPY l2tp_client.c /srv/tunneldigger/client/l2tp_client.c
COPY libasyncns /srv/tunneldigger/client/libasyncns

RUN apt-get update && \
    apt-get install -y \
        cmake build-essential iproute2 pkg-config curl bison flex && \
    mkdir -p /srv/libnl && \
    cd /srv/libnl && \
    curl -sL https://github.com/thom311/libnl/releases/download/libnl3_4_0/libnl-3.4.0.tar.gz \
        | tar -zxf - && \
    cd * && \
    ./configure --prefix=/usr \
            --sysconfdir=/etc \
            --disable-static && \
    make && \
    make install && \
    cd / && \
    rm -rf /srv/libnl && \
    cd /srv/tunneldigger/client/ && \
    cmake . && \
    make && \
    mv tunneldigger /usr/local/bin/tunneldigger && \
    apt-get -y purge cmake build-essential pkg-config curl && \
    apt-get -y autoremove

COPY docker/* /srv/tunneldigger/client/

ENTRYPOINT ["/srv/tunneldigger/client/run.sh"]

