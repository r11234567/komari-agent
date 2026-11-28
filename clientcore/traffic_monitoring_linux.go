package clientcore

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/internal/trafficwatch"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
)

// Keep snapshots outside the Agent state trees that Host may transfer to an
// unprivileged service account during a local identity change.
const managedTrafficRoot = "/var/lib/komari-traffic-monitoring"

func (c *Client) trafficMonitoringStatus() *reportv1.TrafficMonitoringStatus {
	if status := c.trafficMonitoring.Load(); status != nil {
		return status
	}
	state := reportv1.TrafficMonitoringState_TRAFFIC_MONITORING_STATE_DISABLED
	if os.Getenv("KOMARI_TRAFFIC_EVIDENCE_INBOX") != "" {
		state = reportv1.TrafficMonitoringState_TRAFFIC_MONITORING_STATE_MANUAL
	} else if os.Geteuid() != 0 {
		state = reportv1.TrafficMonitoringState_TRAFFIC_MONITORING_STATE_REQUIRES_ROOT
	}
	return &reportv1.TrafficMonitoringStatus{State: state}
}

func (c *Client) monitoringEnabled() bool {
	if c.hostManifest == nil || c.hostTrust == nil || c.privilegedStore == nil {
		return false
	}
	settings := c.privilegedStore.Effective()
	if !settings.TrafficMonitoringEnabled || settings.RequiredPrivilegeMode != reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_ROOT {
		return false
	}
	policy, err := hostops.ReadPolicy(c.hostManifest)
	return err == nil && policy.PrivilegeMode == int32(settings.RequiredPrivilegeMode) &&
		(policy.HostSettings == nil || c.privilegedStore.State().AppliedRevision > policy.HostRevision || policy.HostSettings.TrafficMonitoringEnabled)
}

func (c *Client) runManagedTrafficMonitoring(ctx context.Context, identity credentials.Identity) {
	if os.Geteuid() != 0 || c.hostManifest == nil || c.hostTrust == nil || c.privilegedStore == nil || identity.EnrolledAt.IsZero() {
		return
	}
	stateDir := filepath.Join(managedTrafficRoot, c.hostManifest.ServiceName)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var config trafficwatch.Config
	var cancel context.CancelFunc
	var stopped chan error
	var nextDiscovery time.Time
	setState := func(state reportv1.TrafficMonitoringState, iface string) {
		c.trafficMonitoring.Store(&reportv1.TrafficMonitoringStatus{State: state, InterfaceName: iface})
	}
	stop := func() {
		if stopped != nil {
			cancel()
			<-stopped
			stopped = nil
		}
	}
	defer stop()

	for {
		if c.monitoringEnabled() {
			if now := time.Now(); !now.Before(nextDiscovery) {
				nextDiscovery = now.Add(30 * time.Second)
				next, err := trafficwatch.AutomaticConfig(stateDir)
				if err != nil {
					stop()
					setState(reportv1.TrafficMonitoringState_TRAFFIC_MONITORING_STATE_NO_DEFAULT_INTERFACE, "")
					log.Printf("Traffic monitoring interface: %v", err)
				} else if stopped == nil || next.Interface != config.Interface || !slices.Equal(next.LocalAddresses, config.LocalAddresses) {
					stop()
					config = next
					var workerCtx context.Context
					workerCtx, cancel = context.WithCancel(ctx)
					stopped = make(chan error, 1)
					setState(reportv1.TrafficMonitoringState_TRAFFIC_MONITORING_STATE_STARTING, config.Interface)
					go c.collectManagedTraffic(workerCtx, identity, config, stopped, setState)
				}
			}
		} else {
			stop()
			nextDiscovery = time.Time{}
			if status := c.trafficMonitoring.Load(); status != nil && status.State != reportv1.TrafficMonitoringState_TRAFFIC_MONITORING_STATE_DISABLED {
				setState(reportv1.TrafficMonitoringState_TRAFFIC_MONITORING_STATE_DISABLED, "")
			}
		}
		select {
		case <-ctx.Done():
			return
		case err := <-stopped:
			cancel()
			stopped = nil
			setState(reportv1.TrafficMonitoringState_TRAFFIC_MONITORING_STATE_CAPTURE_UNAVAILABLE, config.Interface)
			log.Printf("Traffic monitoring capture stopped: %v", err)
		case <-ticker.C:
		}
	}
}

func (c *Client) collectManagedTraffic(ctx context.Context, identity credentials.Identity, config trafficwatch.Config, stopped chan<- error, setState func(reportv1.TrafficMonitoringState, string)) {
	if err := hostops.TrustedPath(filepath.Dir(managedTrafficRoot)); err != nil {
		stopped <- err
		return
	}
	if err := os.Mkdir(managedTrafficRoot, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		stopped <- err
		return
	}
	if err := hostops.TrustedPath(managedTrafficRoot); err != nil {
		stopped <- err
		return
	}
	uploadCtx, cancel := context.WithCancel(ctx)
	var uploadDone chan struct{}
	err := trafficwatch.RunWithReady(ctx, config, func() {
		uploadDone = make(chan struct{})
		go func() {
			defer close(uploadDone)
			c.runTrafficEvidence(uploadCtx, identity, config.StateDir)
		}()
		setState(reportv1.TrafficMonitoringState_TRAFFIC_MONITORING_STATE_RUNNING, config.Interface)
	})
	cancel()
	if uploadDone != nil {
		<-uploadDone
	}
	stopped <- err
}
