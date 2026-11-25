package clientcore

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/core/credentials"
	unit "github.com/komari-monitor/komari-agent/monitoring/unit"
	metricsv1 "github.com/r11234567/komari-proto/gen/go/komari/metrics/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const agentTrafficAccountingHeader = "X-Komari-Agent-Traffic-Accounting"

func (c *Client) runTrafficSamples(ctx context.Context, identity credentials.Identity) {
	binding := sha256.Sum256([]byte(identity.Endpoint + "\n" + identity.AgentID + "\n" + identity.PublicKey + "\n" + identity.EnrolledAt.UTC().Format(time.RFC3339Nano)))
	dir := filepath.Join(filepath.Dir(c.credentialStore.Path()), fmt.Sprintf("traffic-pending-%x", binding[:16]))
	spool, release, err := openTrafficSpool(dir)
	if err != nil {
		log.Printf("Traffic queue unavailable: %v", err)
		return
	}
	defer release()
	defer unit.SetPanelTrafficAccounting(false)
	if spool.state.Enabled {
		unit.SetPanelTrafficAccounting(true)
	}
	ready := make(chan struct{}, 1)
	uploaderDone := make(chan struct{})
	go func() {
		defer close(uploaderDone)
		c.uploadTrafficSamples(ctx, identity.AgentID, spool, ready)
	}()
	defer func() { <-uploaderDone }()
	ticker := time.NewTicker(trafficSampleInterval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		sample, err := unit.CollectTrafficSample()
		if err == nil {
			err = spool.add(trafficSampleToProto(sample))
		}
		if err != nil {
			log.Printf("Traffic sample unavailable: %v", err)
			if gapErr := spool.noteGap(time.Now().UTC()); gapErr != nil {
				log.Printf("Could not persist traffic sampling gap: %v", gapErr)
			}
		}
		select {
		case ready <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func trafficSampleToProto(sample *unit.TrafficCounterSample) *metricsv1.TrafficSample {
	result := &metricsv1.TrafficSample{ObservedAt: timestamppb.New(sample.ObservedAt), BootId: sample.BootID}
	if !sample.BootedAt.IsZero() {
		result.BootedAt = timestamppb.New(sample.BootedAt)
	}
	for _, nic := range sample.Interfaces {
		result.Interfaces = append(result.Interfaces, &metricsv1.TrafficInterfaceSample{
			InterfaceId: nic.ID, SentBytes: nic.SentBytes, ReceivedBytes: nic.ReceivedBytes,
		})
	}
	return result
}

func (c *Client) uploadTrafficSamples(ctx context.Context, agentID string, spool *trafficSpool, ready <-chan struct{}) {
	var retry retryPolicy
	for ctx.Err() == nil {
		samples, err := spool.batch(time.Now().UTC())
		if err == nil && len(samples) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-ready:
				continue
			}
		}
		if err == nil {
			var through uint64
			through, err = c.submitTrafficSamples(ctx, agentID, spool.state.Stream, samples)
			if err == nil {
				err = spool.acknowledge(samples, through)
			}
		}
		if err == nil {
			unit.SetPanelTrafficAccounting(true)
			retry.Reset()
			continue
		}
		if isUnsupported(err) {
			// A panel may upgrade while this Agent remains connected.
			if !waitTraffic(ctx, configPollInterval) {
				return
			}
			continue
		}
		logTransientRejection("traffic sample submission", err)
		if !retry.Wait(ctx, err) {
			return
		}
	}
}

func (c *Client) submitTrafficSamples(ctx context.Context, agentID, stream string, samples []*metricsv1.TrafficSample) (uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, requestDeadline)
	defer cancel()
	req := connect.NewRequest(&metricsv1.SubmitTrafficSamplesRequest{AgentId: agentID, StreamId: stream, Samples: samples})
	c.authorize(req.Header())
	response, err := c.metrics.SubmitTrafficSamples(ctx, req)
	if err != nil {
		return 0, err
	}
	return response.Msg.AcceptedSequence, nil
}

func waitTraffic(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
