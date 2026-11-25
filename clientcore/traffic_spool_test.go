package clientcore

import (
	"path/filepath"
	"testing"
	"time"

	metricsv1 "github.com/r11234567/komari-proto/gen/go/komari/metrics/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestTrafficSpoolRetainsUnacknowledgedSamplesAcrossRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pending")
	spool, closeSpool, err := openTrafficSpool(dir)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC()
	for i := range 3 {
		if err := spool.add(&metricsv1.TrafficSample{ObservedAt: timestamppb.New(start.Add(time.Duration(i) * time.Second))}); err != nil {
			t.Fatal(err)
		}
	}
	stream := spool.state.Stream
	closeSpool()
	spool, closeSpool, err = openTrafficSpool(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSpool()
	if spool.state.Stream != stream {
		t.Fatal("restart changed the stream identity")
	}
	samples, err := spool.batch(start)
	if err != nil || len(samples) != 3 || samples[2].Sequence != 3 {
		t.Fatalf("replayed samples: %v, %v", samples, err)
	}
	if err := spool.acknowledge(samples, 4); err == nil {
		t.Fatal("ACK outside the submitted batch was accepted")
	}
	if err := spool.acknowledge(samples, 2); err != nil {
		t.Fatal(err)
	}
	samples, err = spool.batch(start)
	if err != nil || len(samples) != 1 || samples[0].Sequence != 3 {
		t.Fatalf("partial ACK removed the wrong prefix: %v, %v", samples, err)
	}
}

func TestTrafficSpoolExpiryInformsPanel(t *testing.T) {
	spool, closeSpool, err := openTrafficSpool(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeSpool()
	start := time.Now().UTC()
	expired := start.Add(-trafficSpoolWindow - time.Second)
	for _, at := range []time.Time{expired, start} {
		if err := spool.add(&metricsv1.TrafficSample{ObservedAt: timestamppb.New(at)}); err != nil {
			t.Fatal(err)
		}
	}
	samples, err := spool.batch(start)
	if err != nil || len(samples) != 1 || samples[0].Sequence != 2 || !samples[0].GapStartedAt.AsTime().Equal(expired) {
		t.Fatalf("missing expiry marker: %v, %v", samples, err)
	}
}
