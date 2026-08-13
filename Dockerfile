FROM alpine:3.21

WORKDIR /app

# Docker buildx 会在构建时自动填充这些变量
ARG TARGETOS
ARG TARGETARCH

RUN addgroup -S komari \
    && adduser -S -D -H -h /app -s /sbin/nologin -G komari komari \
    && mkdir -p /var/lib/komari \
    && chown komari:komari /app /var/lib/komari

COPY --chmod=755 --chown=komari:komari komari-agent-${TARGETOS}-${TARGETARCH} /app/komari-agent

RUN touch /.komari-agent-container

ENV AGENT_AUTO_DISCOVERY_FILE=/var/lib/komari/auto-discovery.json

USER komari

ENTRYPOINT ["/app/komari-agent"]
# 运行时请指定参数
# Please specify parameters at runtime.
# Return-route probing needs the narrowly scoped NET_RAW capability:
# docker run --cap-add NET_RAW komari-agent -e example.com -t token
CMD ["--help"]
