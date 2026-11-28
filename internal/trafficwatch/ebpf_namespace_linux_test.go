package trafficwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestAutomaticEBPFPublishesInterfaceTraffic(t *testing.T) {
	const key = "KOMARI_TEST_TCX_STATE"
	if state := os.Getenv(key); state != "" {
		cfg, err := AutomaticConfig(state)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Interface != "edge0" {
			t.Fatalf("selected %s, expected edge0", cfg.Interface)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
		defer cancel()
		if err := RunWithReady(ctx, cfg, func() {
			if err := os.WriteFile(filepath.Join(state, "ready"), nil, 0600); err != nil {
				t.Error(err)
				cancel()
			}
		}); err != nil {
			t.Fatal(err)
		}
		return
	}
	if os.Getenv("KOMARI_TEST_TCX") != "1" {
		t.Skip("requires Linux TCX and isolated network namespaces")
	}

	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}
	suffix := fmt.Sprint(os.Getpid())
	node, peer := "komari-node-"+suffix, "komari-peer-"+suffix
	for _, ns := range []string{node, peer} {
		run("netns", "add", ns)
		t.Cleanup(func() { run("netns", "del", ns) })
	}
	run("link", "add", "edge0", "netns", node, "type", "veth", "peer", "name", "peer0", "netns", peer)
	run("-n", node, "addr", "add", "192.0.2.1/24", "dev", "edge0")
	run("-n", peer, "addr", "add", "192.0.2.2/24", "dev", "peer0")
	run("-n", node, "addr", "add", "2001:db8::1/64", "dev", "edge0", "nodad")
	run("-n", peer, "addr", "add", "2001:db8::2/64", "dev", "peer0", "nodad")
	run("-n", node, "link", "set", "edge0", "up")
	run("-n", peer, "link", "set", "peer0", "up")
	run("-n", node, "route", "add", "default", "via", "192.0.2.2")
	run("-n", node, "-6", "route", "add", "default", "via", "2001:db8::2", "dev", "edge0")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(t.TempDir(), "collector.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	child := exec.Command("ip", "netns", "exec", node, "env", key+"="+state, binary, "-test.run=^TestAutomaticEBPFPublishesInterfaceTraffic$", "-test.v")
	child.Stdout, child.Stderr = log, log
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	fail := func(message string) {
		body, _ := os.ReadFile(log.Name())
		t.Fatalf("%s\n%s", message, body)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if _, err := os.Stat(filepath.Join(state, "ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			fail("TCX collector did not attach")
		}
	}

	// Add addresses after the automatic collector has populated its local
	// address map. Traffic to and from both still belongs to the same interface.
	run("-n", node, "addr", "add", "192.0.2.9/24", "dev", "edge0")
	run("-n", node, "addr", "add", "2001:db8::9/64", "dev", "edge0", "nodad")
	sender := `import socket,sys
src,dst=sys.argv[1:]
s=socket.socket(socket.AF_INET6 if ':' in src else socket.AF_INET,socket.SOCK_DGRAM)
s.bind((src,0))
for _ in range(10): s.sendto(b'x'*1000,(dst,29122))
`
	for _, pair := range [][3]string{
		{peer, "192.0.2.2", "192.0.2.9"}, {node, "192.0.2.9", "192.0.2.2"},
		{peer, "2001:db8::2", "2001:db8::9"}, {node, "2001:db8::9", "2001:db8::2"},
	} {
		if out, err := exec.Command("ip", "netns", "exec", pair[0], "python3", "-c", sender, pair[1], pair[2]).CombinedOutput(); err != nil {
			t.Fatalf("send UDP %v: %v: %s", pair, err, out)
		}
	}
	var found bool
	// 10x IPv4 UDP (28 B headers) plus 10x IPv6 UDP (48 B).
	const directionMinimum = 20*1000 + 10*(28+48)
	for deadline := time.Now().Add(42 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		paths, _ := filepath.Glob(filepath.Join(state, "hour-*.json"))
		var rx, tx, unmatched uint64
		for _, path := range paths {
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var hour hourSummary
			if err := json.Unmarshal(body, &hour); err != nil {
				t.Fatal(err)
			}
			if hour.Coverage == nil || hour.Coverage.Scope != "interface_ip" {
				t.Fatalf("wrong coverage %+v", hour.Coverage)
			}
			rx += hour.Observed.RX
			tx += hour.Observed.TX
			unmatched += hour.Coverage.Unmatched
		}
		if rx >= directionMinimum && tx >= directionMinimum && unmatched >= 2*directionMinimum {
			t.Logf("live while agent is running: RX=%d, TX=%d, unmatched=%d; per-direction test floor=%d bytes", rx, tx, unmatched, directionMinimum)
			found = true
			break
		}
	}
	if !found {
		fail("IPv4/IPv6 bytes outside configured addresses did not appear in live hour")
	}
}
