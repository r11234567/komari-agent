FROM debian:13-slim AS debian13
RUN apt-get update \
    && apt-get install -y --no-install-recommends nfdump iproute2 python3 curl util-linux \
    && apt-get clean

FROM rockylinux/rockylinux:9 AS rocky9
RUN dnf -y install epel-release \
    && dnf -y install nfdump iproute python3 util-linux curl-minimal \
    && dnf clean all
