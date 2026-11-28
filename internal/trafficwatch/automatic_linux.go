package trafficwatch

import (
	"errors"
	"net"
	"net/netip"
	"slices"
)

// AutomaticConfig finds the interface used by the default Internet route.
// Connecting a UDP socket selects a route and source address without sending
// a packet. Prefer IPv4 and capture both address families on the chosen link.
func AutomaticConfig(stateDir string) (Config, error) {
	var sources []netip.Addr
	for _, dst := range []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:9"), netip.MustParseAddrPort("[2001:db8::1]:9")} {
		conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(dst))
		if err == nil {
			sources = append(sources, conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap())
			_ = conn.Close()
		}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return Config{}, err
	}
	var fallback Config
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			continue
		}
		// The embedded sampler parses Ethernet headers.
		if len(iface.HardwareAddr) != 6 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		var addresses []netip.Addr
		for _, addr := range addrs {
			prefix, err := netip.ParsePrefix(addr.String())
			if err == nil && prefix.Addr().IsGlobalUnicast() {
				addresses = append(addresses, prefix.Addr().Unmap())
			}
		}
		for priority, source := range sources {
			if !slices.Contains(addresses, source) {
				continue
			}
			cfg := automaticConfigForInterface(iface.Name, source, addresses, stateDir)
			if priority == 0 {
				return cfg, nil
			}
			// Keep looking for the interface selected by the preferred route.
			fallback = cfg
		}
	}
	if fallback.Interface != "" {
		return fallback, nil
	}
	return Config{}, errors.New("no supported default-route Ethernet interface")
}

func automaticConfigForInterface(name string, source netip.Addr, addresses []netip.Addr, stateDir string) Config {
	slices.SortFunc(addresses, netip.Addr.Compare)
	addresses = slices.Compact(addresses)
	local := []netip.Addr{source}
	for _, addr := range addresses {
		if addr != source && len(local) < 16 {
			local = append(local, addr)
		}
	}
	return Config{
		Sampler: "ebpf", Interface: name, LocalAddresses: local, StateDir: stateDir,
		Thresholds: defaultThresholds(),
	}
}
