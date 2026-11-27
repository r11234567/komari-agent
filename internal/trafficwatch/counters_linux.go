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
	Unit                string `json:"unit"`
	Group               string `json:"group"`
	PublicInterfaceOnly bool   `json:"public_interface_only,omitempty"`
}

type counterValue struct {
	instance string
	n        Traffic
}

type localCounters struct {
	xray         *xrayStats
	lastXray     map[string]uint64
	lastServices map[string]counterValue
}

func (c *localCounters) close() {
	if c.xray != nil {
		c.xray.transport.CloseIdleConnections()
	}
}

func (c *localCounters) read(ctx context.Context, cfg Config) evidence {
	result := evidence{services: make(map[string]Traffic), serviceTotals: make(map[string]Traffic)}
	type xrayResult struct {
		count proxyTraffic
		err   error
	}
	var xrayDone chan xrayResult
	if cfg.Xray != nil {
		xrayDone = make(chan xrayResult, 1)
		go func() {
			deadline, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			count, err := c.readXray(deadline, *cfg.Xray)
			xrayDone <- xrayResult{count, err}
		}()
	}
	if len(cfg.Services) != 0 {
		deadline, cancel := context.WithTimeout(ctx, 3*time.Second)
		active, err := readServices(deadline, cfg.Services)
		cancel()
		result.servicePartial = err != nil
		c.addServices(&result, cfg.Services, active)
	}
	if xrayDone != nil {
		proxy := <-xrayDone
		result.xray = proxy.count
		result.partial = result.partial || proxy.err != nil
	}
	return result
}

func (c *localCounters) addServices(result *evidence, configured []ServiceConfig, active map[string]counterValue) {
	if c.lastServices == nil {
		c.lastServices = make(map[string]counterValue)
	}
	for _, service := range configured {
		current, sampled := active[service.Unit]
		if !sampled {
			delete(c.lastServices, service.Unit)
			result.partial = result.partial || service.PublicInterfaceOnly
			result.servicePartial = true
			continue
		}
		old, ok := c.lastServices[service.Unit]
		c.lastServices[service.Unit] = current
		delta, complete := serviceDelta(old, current, ok)
		result.servicePartial = result.servicePartial || !complete
		result.serviceTotals[service.Group] = result.serviceTotals[service.Group].add(delta)
		if service.PublicInterfaceOnly {
			result.services[service.Group] = result.services[service.Group].add(delta)
			result.partial = result.partial || !complete
		}
	}
}

func serviceDelta(old, current counterValue, known bool) (Traffic, bool) {
	switch {
	case current.instance == "":
		return Traffic{}, true // Inactive and no final counters were retained.
	case !known:
		return Traffic{}, false // No evidence for when this invocation started.
	case old.instance == "":
		return current.n, true
	case current.instance != old.instance:
		return current.n, false // The previous invocation's tail may be missing.
	case current.n.RX < old.n.RX || current.n.TX < old.n.TX:
		return Traffic{}, false
	default:
		return Traffic{RX: current.n.RX - old.n.RX, TX: current.n.TX - old.n.TX}, true
	}
}

func (c *localCounters) readXray(ctx context.Context, cfg XrayConfig) (proxyTraffic, error) {
	if err := cfg.checkPolicy(); err != nil {
		c.lastXray = nil
		return proxyTraffic{}, err
	}
	if c.xray == nil {
		c.xray = newXrayStats(cfg.Endpoint)
	}
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
	type reading struct {
		key   string
		dest  *uint64
		value uint64
		err   error
	}
	const maxXrayCounters = 16
	readings := make(chan reading, maxXrayCounters)
	var pending int
	for _, field := range fields {
		for _, tag := range field.tags {
			key := strings.Join([]string{field.side, tag, "traffic", field.direction}, ">>>")
			pending++
			go func() {
				n, err := c.xray.counter(ctx, key)
				readings <- reading{key: key, dest: field.dest, value: n, err: err}
			}()
		}
	}
	values := make(map[string]uint64, pending)
	reset := c.lastXray == nil
	var readErr error
	for range pending {
		result := <-readings
		if result.err != nil {
			readErr = result.err
			continue
		}
		values[result.key] = result.value
		if old := c.lastXray[result.key]; result.value >= old {
			*result.dest += result.value - old
		} else {
			reset = true
		}
	}
	if readErr != nil {
		c.lastXray = nil
		return proxyTraffic{}, readErr
	}
	c.lastXray = values
	if reset {
		return proxyTraffic{}, errors.New("Xray counters need a new baseline")
	}
	return delta, nil
}

func readServices(ctx context.Context, units []ServiceConfig) (map[string]counterValue, error) {
	args := []string{"show", "--no-pager", "-p", "Id", "-p", "Names", "-p", "LoadState", "-p", "ActiveState",
		"-p", "InvocationID", "-p", "IPAccounting", "-p", "IPIngressBytes", "-p", "IPEgressBytes", "--"}
	for _, unit := range units {
		args = append(args, unit.Unit)
	}
	out, err := exec.CommandContext(ctx, "systemctl", args...).Output()
	// systemctl may print healthy units even when one of the requested units
	// does not exist. Preserve those units and let the caller mark the gap.
	return parseServiceCounters(string(out)), err
}

func parseServiceCounters(output string) map[string]counterValue {
	result := make(map[string]counterValue)
	for _, block := range strings.Split(output, "\n\n") {
		fields := make(map[string]string)
		for _, line := range strings.Split(block, "\n") {
			if key, value, found := strings.Cut(line, "="); found {
				fields[key] = value
			}
		}
		current, ok := serviceCounter(fields)
		if !ok {
			continue
		}
		for _, name := range append(strings.Fields(fields["Names"]), fields["Id"]) {
			if name != "" {
				result[name] = current
			}
		}
	}
	return result
}

func serviceCounter(fields map[string]string) (counterValue, bool) {
	if fields["LoadState"] != "loaded" || fields["IPAccounting"] != "yes" {
		return counterValue{}, false
	}
	inactive := fields["ActiveState"] == "inactive" || fields["ActiveState"] == "failed"
	id := fields["InvocationID"]
	hasInvocation := strings.Trim(id, "0") != ""
	rx, rxErr := strconv.ParseUint(fields["IPIngressBytes"], 10, 63)
	tx, txErr := strconv.ParseUint(fields["IPEgressBytes"], 10, 63)
	if rxErr == nil && txErr == nil && hasInvocation {
		return counterValue{instance: id, n: Traffic{RX: rx, TX: tx}}, true
	}
	return counterValue{}, inactive
}
