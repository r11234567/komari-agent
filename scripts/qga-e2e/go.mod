module github.com/komari-monitor/komari-agent/scripts/qga-e2e

go 1.26.0

require (
	github.com/komari-monitor/komari-agent v0.0.0
	github.com/r11234567/komari-proto v0.0.0
)

require (
	github.com/cilium/ebpf v0.20.0 // indirect
	github.com/cloudflare/circl v1.6.4 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
)

replace github.com/komari-monitor/komari-agent => ../..

replace github.com/r11234567/komari-proto => ../../.qga-proto
