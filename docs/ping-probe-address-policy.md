# Ping probe destinations

The Agent permits public addresses by default for ICMP, TCP, and HTTP probes. It checks resolved addresses before connecting. HTTP probes send one request to the resolved address and do not follow redirects.

For a private monitoring target, add its exact IP to `KOMARI_PING_PROBE_ALLOW_IPS` in the Agent service environment and restart the Agent. Use commas to list multiple IPs. For example, a systemd drop-in can contain:

```ini
[Service]
Environment="KOMARI_PING_PROBE_ALLOW_IPS=192.168.20.10,fd12:3456::20"
```

On an installation managed by systemd, place the drop-in with `sudo systemctl edit komari-agent.service`, then run `sudo systemctl restart komari-agent.service`. On other platforms set the same environment variable in the service manager.

The permission applies to all probe protocols and ports on each listed IP. Unspecified, multicast, and link-local addresses are unavailable. A malformed list causes probes to fail until corrected. On the panel, a blocked destination is recorded as an unsuccessful probe.
