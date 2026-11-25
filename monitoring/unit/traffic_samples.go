package monitoring

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
	"github.com/komari-monitor/komari-agent/monitoring/netstatic"
	"github.com/shirou/gopsutil/v4/host"
	systemnet "github.com/shirou/gopsutil/v4/net"
)

var trafficAccountingMode struct {
	sync.Mutex
	panel bool
}

func SetPanelTrafficAccounting(enabled bool) {
	trafficAccountingMode.Lock()
	defer trafficAccountingMode.Unlock()
	if enabled && !trafficAccountingMode.panel {
		if err := netstatic.Stop(); err != nil {
			log.Printf("Could not stop legacy traffic collection: %v", err)
		}
	}
	trafficAccountingMode.panel = enabled
}

type TrafficCounterSample struct {
	ObservedAt time.Time
	BootedAt   time.Time
	BootID     string
	Interfaces []TrafficInterface
}

type TrafficInterface struct {
	ID            string
	SentBytes     uint64
	ReceivedBytes uint64
}

func CollectTrafficSample() (*TrafficCounterSample, error) {
	config := runtimeconfig.Current()
	include, exclude := nicPatterns(config.IncludeNics), nicPatterns(config.ExcludeNics)
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	ids := make(map[string]string, len(interfaces))
	for _, nic := range interfaces {
		if len(nic.HardwareAddr) != 0 {
			ids[nic.Name] = nic.Name + "/" + nic.HardwareAddr.String()
		} else {
			ids[nic.Name] = fmt.Sprintf("%s/%d", nic.Name, nic.Index)
		}
	}
	counters, err := systemnet.IOCounters(true)
	if err != nil {
		return nil, err
	}
	if len(counters) == 0 {
		return nil, fmt.Errorf("no network interfaces found")
	}
	observed := time.Now().UTC()
	sample := &TrafficCounterSample{ObservedAt: observed}
	if runtime.GOOS == "linux" {
		if bootID, err := os.ReadFile(filepath.Join(procRoot(), "sys", "kernel", "random", "boot_id")); err == nil {
			sample.BootID = strings.TrimSpace(string(bootID))
		}
	}
	if bootTime, err := host.BootTime(); err == nil && bootTime > 0 && int64(bootTime) <= observed.Unix() {
		sample.BootedAt = time.Unix(int64(bootTime), 0).UTC()
		if sample.BootID == "" && (runtime.GOOS == "darwin" || runtime.GOOS == "freebsd") {
			sample.BootID = sample.BootedAt.Format(time.RFC3339)
		}
	}
	for _, nic := range counters {
		if id := ids[nic.Name]; id != "" && shouldInclude(nic.Name, include, exclude) {
			sample.Interfaces = append(sample.Interfaces, TrafficInterface{ID: id, SentBytes: nic.BytesSent, ReceivedBytes: nic.BytesRecv})
		}
	}
	if len(sample.Interfaces) > 64 {
		return nil, fmt.Errorf("traffic sampling supports 64 selected interfaces")
	}
	return sample, nil
}
