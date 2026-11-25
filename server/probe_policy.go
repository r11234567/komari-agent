package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
)

const probeAllowIPsEnv = "KOMARI_PING_PROBE_ALLOW_IPS"

var nonPublicProbePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

func probeAddressAllowed(address netip.Addr, localAllowed map[netip.Addr]struct{}) bool {
	address = address.Unmap()
	if !address.IsValid() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() {
		return false
	}
	if _, ok := localAllowed[address]; ok {
		return true
	}
	if !address.IsGlobalUnicast() || address.IsPrivate() {
		return false
	}
	for _, prefix := range nonPublicProbePrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func localProbeAddresses() (map[netip.Addr]struct{}, error) {
	allowed := map[netip.Addr]struct{}{}
	setting := strings.TrimSpace(os.Getenv(probeAllowIPsEnv))
	if setting == "" {
		return allowed, nil
	}
	for _, value := range strings.Split(setting, ",") {
		address, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || address.Zone() != "" {
			return nil, fmt.Errorf("invalid IP in %s", probeAllowIPsEnv)
		}
		allowed[address.Unmap()] = struct{}{}
	}
	return allowed, nil
}

func resolveProbeAddress(ctx context.Context, target string, lookup func(context.Context, string, string) ([]netip.Addr, error)) (string, error) {
	allowed, err := localProbeAddresses()
	if err != nil {
		return "", err
	}
	if address, err := netip.ParseAddr(target); err == nil {
		if probeAddressAllowed(address, allowed) {
			return address.Unmap().String(), nil
		}
		return "", errors.New("probe destination is blocked by local address policy")
	}
	addresses, err := lookup(ctx, "ip", target)
	if err != nil {
		return "", fmt.Errorf("resolve probe destination: %w", err)
	}
	for _, address := range addresses {
		if probeAddressAllowed(address, allowed) {
			return address.Unmap().String(), nil
		}
	}
	return "", errors.New("probe destination has no permitted address")
}

func resolveIP(ctx context.Context, target string) (string, error) {
	return resolveProbeAddress(ctx, target, net.DefaultResolver.LookupNetIP)
}
