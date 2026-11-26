FROM debian:13-slim AS debian13-ebpf
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 python3 curl util-linux \
    && apt-get clean

FROM debian13-ebpf AS debian13
RUN apt-get install -y --no-install-recommends nfdump && apt-get clean

FROM rockylinux/rockylinux:9 AS rocky9-ebpf
RUN dnf -y install iproute python3 util-linux curl-minimal && dnf clean all

FROM rocky9-ebpf AS rocky9
RUN dnf -y install epel-release \
    && dnf -y install nfdump \
    && dnf clean all

FROM alpine:3.22 AS alpine-capture-build
RUN apk add --no-cache autoconf automake libtool build-base bison flex curl \
        libpcap-dev libbz2 zlib-dev bzip2-dev lz4-dev zstd-dev linux-headers
WORKDIR /src
# Alpine's nfdump 1.7.6 package omits nfpcapd. Build both binaries for musl.
RUN curl -fsSL https://codeload.github.com/phaag/nfdump/tar.gz/refs/tags/v1.7.6 -o nfdump.tar.gz \
    && echo '2d25220d7a48f57ba65f228fb5d2eb4d2a0ab2b352a037ed6249b39cf68c1b9a  nfdump.tar.gz' | sha256sum -c - \
    && tar -xzf nfdump.tar.gz --strip-components=1 \
    && sed -i 's|^#include <linux/if_ether.h>$|#include <netinet/if_ether.h>|' src/nfpcapd/packet_linux.c \
    && ./autogen.sh && ./configure --enable-nfpcapd \
    && make -j2 && make DESTDIR=/stage install

FROM alpine:3.22 AS alpine322-ebpf
RUN apk add --no-cache iproute2 python3 curl util-linux

FROM alpine322-ebpf AS alpine322
COPY --from=alpine-capture-build /stage/usr/local/ /usr/local/
RUN apk add --no-cache libpcap libbz2 zlib lz4-libs zstd-libs \
    && command -v nfpcapd && command -v nfdump
