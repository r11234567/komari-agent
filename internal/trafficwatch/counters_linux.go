package trafficwatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type XrayConfig struct {
	Endpoint     string   `json:"endpoint"`
	PolicyFile   string   `json:"policy_file"`
	InboundTags  []string `json:"inbound_tags"`
	OutboundTags []string `json:"outbound_tags"`
	PublicLegs   string   `json:"public_legs"`
}

func (x XrayConfig) validate() error {
	host, port, err := net.SplitHostPort(x.Endpoint)
	ip, ipErr := netip.ParseAddr(host)
	number, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || ipErr != nil || portErr != nil || number == 0 || !ip.IsLoopback() {
		return errors.New("xray endpoint must be a numeric loopback address and port")
	}
	if x.PublicLegs != "inbound" && x.PublicLegs != "outbound" && x.PublicLegs != "both" {
		return errors.New("xray public_legs must be inbound, outbound or both")
	}
	for _, tags := range [][]string{x.InboundTags, x.OutboundTags} {
		seen := make(map[string]bool)
		if len(tags) == 0 || len(tags) > 4 {
			return errors.New("xray requires one to four explicit tags on each side")
		}
		for _, tag := range tags {
			if tag == "" || len(tag) > 64 || strings.ContainsAny(tag, ">\r\n\x00") || seen[tag] {
				return errors.New("invalid or duplicate xray tag")
			}
			seen[tag] = true
		}
	}
	if !filepath.IsAbs(x.PolicyFile) {
		return errors.New("xray policy_file must be an absolute path to the active aggregate policy fragment")
	}
	return x.checkPolicy()
}

func (x XrayConfig) checkPolicy() error {
	raw, err := readBoundedFile(x.PolicyFile, 64<<10)
	if err != nil {
		return fmt.Errorf("read Xray policy fragment: %w", err)
	}
	var fragment struct {
		Stats  map[string]json.RawMessage `json:"stats"`
		Policy struct {
			System map[string]bool           `json:"system"`
			Levels map[string]map[string]any `json:"levels"`
		} `json:"policy"`
	}
	if err = json.Unmarshal(raw, &fragment); err != nil || fragment.Stats == nil {
		return errors.New("Xray policy fragment must enable aggregate statistics")
	}
	for _, flag := range []string{"statsInboundUplink", "statsInboundDownlink", "statsOutboundUplink", "statsOutboundDownlink"} {
		if !fragment.Policy.System[flag] {
			return fmt.Errorf("Xray policy fragment has disabled %s", flag)
		}
	}
	for _, level := range fragment.Policy.Levels {
		for name, value := range level {
			if strings.HasPrefix(strings.ToLower(name), "statsuser") && value != false {
				return errors.New("Xray user statistics must be disabled in the policy fragment")
			}
		}
	}
	return nil
}

type ServiceConfig struct {
	Unit  string `json:"unit"`
	Group string `json:"group"`
}

type counterValue struct {
	instance string
	n        Traffic
}

type localCounters struct {
	lastXray     map[string]uint64
	lastServices map[string]counterValue
}

func (c *localCounters) read(ctx context.Context, cfg Config) evidence {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	result := evidence{services: make(map[string]Traffic)}
	if cfg.Xray != nil {
		var err error
		result.xray, err = c.readXray(ctx, *cfg.Xray)
		if err != nil {
			result.partial = true
		}
	}
	if c.lastServices == nil {
		c.lastServices = make(map[string]counterValue)
	}
	for _, service := range cfg.Services {
		current, err := readService(ctx, service.Unit)
		if err != nil {
			delete(c.lastServices, service.Unit)
			result.partial = true
			continue
		}
		old, ok := c.lastServices[service.Unit]
		c.lastServices[service.Unit] = current
		if !ok || current.instance != old.instance || current.n.RX < old.n.RX || current.n.TX < old.n.TX {
			result.partial = true
			continue
		}
		delta := Traffic{RX: current.n.RX - old.n.RX, TX: current.n.TX - old.n.TX}
		result.services[service.Group] = result.services[service.Group].add(delta)
	}
	return result
}

func (c *localCounters) readXray(ctx context.Context, cfg XrayConfig) (proxyTraffic, error) {
	if err := cfg.checkPolicy(); err != nil {
		c.lastXray = nil
		return proxyTraffic{}, err
	}
	values := make(map[string]uint64)
	var delta proxyTraffic
	fields := []struct {
		side, direction string
		tags            []string
		dest            *uint64
	}{
		{"inbound", "uplink", cfg.InboundTags, &delta.InUp},
		{"inbound", "downlink", cfg.InboundTags, &delta.InDown},
		{"outbound", "uplink", cfg.OutboundTags, &delta.OutUp},
		{"outbound", "downlink", cfg.OutboundTags, &delta.OutDown},
	}
	reset := c.lastXray == nil
	for _, field := range fields {
		for _, tag := range field.tags {
			key := strings.Join([]string{field.side, tag, "traffic", field.direction}, ">>>")
			n, err := getXrayCounter(ctx, cfg.Endpoint, key)
			if err != nil {
				c.lastXray = nil
				return proxyTraffic{}, err
			}
			values[key] = n
			if old := c.lastXray[key]; n >= old {
				*field.dest += n - old
			} else {
				reset = true
			}
		}
	}
	c.lastXray = values
	if reset {
		return proxyTraffic{}, errors.New("Xray counters need a new baseline")
	}
	return delta, nil
}

// QueryStats applies a substring filter. GetStats requests an exact, explicitly
// allowed aggregate name and cannot return a user counter with a similar name.
func getXrayCounter(ctx context.Context, endpoint, key string) (uint64, error) {
	cmd := exec.CommandContext(ctx, "xray", "api", "stats", "-server="+endpoint, "-name="+key, "-reset=false", "-timeout=2")
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && strings.Contains(string(exitErr.Stderr), "code = NotFound") {
			return 0, nil // Xray may create a counter lazily on first use.
		}
		return 0, errors.New("Xray GetStats is unavailable")
	}
	var result struct {
		Stat struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
		} `json:"stat"`
	}
	if len(out) > 4096 || json.Unmarshal(out, &result) != nil || result.Stat.Name != key {
		return 0, errors.New("unexpected Xray aggregate response")
	}
	if len(result.Stat.Value) == 0 {
		return 0, nil
	}
	return strconv.ParseUint(strings.Trim(string(result.Stat.Value), "\""), 10, 63)
}

func readService(ctx context.Context, unit string) (counterValue, error) {
	out, err := exec.CommandContext(ctx, "systemctl", "show",
		"--property=ActiveState,InvocationID,IPIngressBytes,IPEgressBytes", "--", unit).Output()
	if err != nil {
		return counterValue{}, err
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		key, value, found := strings.Cut(line, "=")
		if found {
			fields[key] = value
		}
	}
	rx, rxErr := strconv.ParseUint(fields["IPIngressBytes"], 10, 63)
	tx, txErr := strconv.ParseUint(fields["IPEgressBytes"], 10, 63)
	if rxErr != nil || txErr != nil {
		if fields["ActiveState"] == "inactive" || fields["ActiveState"] == "failed" {
			return counterValue{instance: fields["InvocationID"]}, nil
		}
		return counterValue{}, errors.New("systemd IPAccounting unavailable")
	}
	return counterValue{instance: fields["InvocationID"], n: Traffic{RX: rx, TX: tx}}, nil
}

func installedXray(cfg Config) error {
	if cfg.Xray != nil {
		_, err := exec.LookPath("xray")
		return err
	}
	return nil
}
