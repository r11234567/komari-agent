package qgatest

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/komari-monitor/komari-agent/internal/qgastream"
	"github.com/r11234567/komari-proto/diagnostics"
)

func TestRealGuestTransport(t *testing.T) {
	socket := os.Getenv("KOMARI_TEST_VM_SOCKET")
	if socket == "" {
		t.Skip("provide the disposable QEMU fixture socket")
	}
	records := dialFixture(t, os.Getenv("KOMARI_TEST_RECORDS_SOCKET"))
	defer records.Close()
	if err := records.SetDeadline(time.Now().Add(7 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	outputStream := bufio.NewReader(records)
	ready, err := outputStream.ReadString('\n')
	if err != nil || ready != "ready\n" {
		t.Fatalf("guest tracer did not become ready: %v", err)
	}
	conn := dialFixture(t, socket)
	defer conn.Close()
	var replies qgastream.Decoder
	if err := conn.SetDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := synchronizeGuest(conn, &replies); err != nil {
		t.Fatalf("QGA stream synchronization failed: %v", err)
	}
	var ordinary map[string]json.RawMessage
	if err := exchange(conn, &replies, []byte("{\"execute\":\"guest-ping\"}\n"), &ordinary, nil); err != nil || ordinary["return"] == nil {
		t.Fatalf("ordinary QGA operation failed: %v", err)
	}
	public, private, err := diagnostics.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	header := diagnostics.Header{Node: [16]byte{1}, Stream: [16]byte{2}, Sequence: 1}
	seal := func(record []byte) ([]byte, error) {
		encoded, err := diagnostics.Seal(public, header, record)
		header.Sequence++
		return encoded, err
	}
	script := strings.Repeat("# disposable fixture\n", 550) + "LC_ALL=C; export LC_ALL; cat /run/komari-fixture/account-*"
	request, err := json.Marshal(map[string]any{"execute": "guest-exec", "arguments": map[string]any{
		"path": "/bin/sh", "arg": []string{"-c", script}, "capture-output": true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	var requests qgastream.Decoder
	var sealedRequest []byte
	for offset := 0; offset < len(request); offset += 127 {
		err := requests.Feed(request[offset:min(offset+127, len(request))], func(frame qgastream.Frame) error {
			var err error
			sealedRequest, err = seal(frame.Bytes)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	var launched struct {
		Return struct {
			PID uint64 `json:"pid"`
		} `json:"return"`
	}
	if err := exchange(conn, &replies, append(bytes.Clone(request), '\n'), &launched, nil); err != nil || launched.Return.PID == 0 {
		t.Fatalf("fixture command did not start: %v", err)
	}
	statusRequest, err := json.Marshal(map[string]any{"execute": "guest-exec-status", "arguments": map[string]uint64{"pid": launched.Return.PID}})
	if err != nil {
		t.Fatal(err)
	}
	type status struct {
		Return struct {
			Exited   bool   `json:"exited"`
			ExitCode *int   `json:"exitcode"`
			Output   string `json:"out-data"`
		} `json:"return"`
	}
	var sealedResponse []byte
	var final status
	for i := 0; i < 25; i++ {
		final = status{}
		err := exchange(conn, &replies, append(bytes.Clone(statusRequest), '\n'), &final, func(raw []byte) error {
			if !final.Return.Exited {
				return nil
			}
			var err error
			sealedResponse, err = seal(raw)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if final.Return.Exited {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	_, requestPlaintext, err := diagnostics.Open(private, sealedRequest)
	if err != nil || !bytes.Equal(requestPlaintext, request) || bytes.Contains(sealedRequest, []byte("disposable fixture")) {
		t.Fatal("sealed request failed byte-for-byte verification")
	}
	_, responsePlaintext, err := diagnostics.Open(private, sealedResponse)
	if err != nil {
		t.Fatal(err)
	}
	var decrypted status
	if err := json.Unmarshal(responsePlaintext, &decrypted); err != nil {
		t.Fatal(err)
	}
	output, err := base64.StdEncoding.DecodeString(decrypted.Return.Output)
	if err != nil || !decrypted.Return.Exited || decrypted.Return.ExitCode == nil || *decrypted.Return.ExitCode != 0 || string(output) != os.Getenv("KOMARI_TEST_FIXTURE_VALUE")+"\n" {
		t.Fatal("sealed QGA response did not match the fixture exit and output")
	}
	verifyGuestRecords(t, records, outputStream, request, responsePlaintext)
	t.Log("Real guest trace sealed the original QGA request and result before leaving the virtual machine")
}

func dialFixture(t *testing.T, path string) net.Conn {
	t.Helper()
	if path == "" {
		t.Fatal("missing fixture socket")
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", path, time.Second)
		if err == nil {
			return conn
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("fixture socket unavailable")
	return nil
}

func synchronizeGuest(conn net.Conn, decoder *qgastream.Decoder) error {
	if _, err := conn.Write([]byte("\xff" + `{"execute":"guest-sync-delimited","arguments":{"id":2173614}}` + "\n")); err != nil {
		return err
	}
	var markerSeen, synchronized bool
	var chunk [79]byte
	for !synchronized {
		n, readErr := conn.Read(chunk[:])
		err := decoder.Feed(chunk[:n], func(frame qgastream.Frame) error {
			if frame.Reset {
				markerSeen = true
				return nil
			}
			if !markerSeen || frame.Lost {
				return nil
			}
			var reply struct {
				Return uint64 `json:"return"`
			}
			if err := json.Unmarshal(frame.Bytes, &reply); err == nil && reply.Return == 2173614 {
				synchronized = true
			}
			return nil
		})
		if err != nil {
			return err
		}
		if readErr != nil && !synchronized {
			return readErr
		}
	}
	return nil
}

func verifyGuestRecords(t *testing.T, conn net.Conn, wire *bufio.Reader, request, response []byte) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	private, err := base64.StdEncoding.DecodeString(os.Getenv("KOMARI_TEST_PANEL_KEY"))
	if err != nil || len(private) != 32 {
		t.Fatal("invalid fixture receiver key")
	}
	decoder := json.NewDecoder(wire)
	var gotRequest, gotResponse bool
	for i := uint64(1); i <= 64; i++ {
		var ciphertext []byte
		if err := decoder.Decode(&ciphertext); err != nil {
			t.Fatalf("read sealed guest observation: %v", err)
		}
		if bytes.Contains(ciphertext, []byte("disposable fixture")) {
			t.Fatal("guest observation contained plaintext")
		}
		for _, sample := range strings.Split(os.Getenv("KOMARI_TEST_FIXTURE_VALUE"), "\n") {
			if sample == "" || bytes.Contains(ciphertext, []byte(sample)) {
				t.Fatal("guest observation exposed generated fixture data")
			}
		}
		header, plaintext, err := diagnostics.Open(private, ciphertext)
		if err != nil || header.Sequence != i {
			t.Fatalf("invalid guest observation %d: %v", i, err)
		}
		var record qgastream.Observation
		if err := json.Unmarshal(plaintext, &record); err != nil || record.Gap || record.ObservedAt.IsZero() || record.Digest != sha256.Sum256(record.Raw) {
			t.Fatalf("invalid observation digest or metadata: %v", err)
		}
		if record.Command != "guest-exec" && record.Command != "guest-exec-status" {
			t.Fatal("collector retained a command outside the tested evidence scope")
		}
		if unread := os.Getenv("KOMARI_TEST_UNREAD_VALUE"); unread == "" || bytes.Contains(record.Raw, []byte(unread)) {
			t.Fatal("collector retained unrelated local data")
		}
		gotRequest = gotRequest || record.Direction == qgastream.Request && bytes.Equal(record.Raw, request)
		gotResponse = gotResponse || record.Direction == qgastream.Response && bytes.Equal(record.Raw, response)
		if gotRequest && gotResponse {
			return
		}
	}
	t.Fatalf("missing passive guest records (request=%t, response=%t)", gotRequest, gotResponse)
}

func exchange(conn net.Conn, decoder *qgastream.Decoder, request []byte, response any, receive func([]byte) error) error {
	if _, err := conn.Write(request); err != nil {
		return err
	}
	sawReply := false
	var chunk [79]byte
	for !sawReply {
		n, readErr := conn.Read(chunk[:])
		err := decoder.Feed(chunk[:n], func(frame qgastream.Frame) error {
			if frame.Lost {
				return errors.New("guest protocol framing lost")
			}
			if frame.Reset {
				return nil
			}
			if sawReply {
				return errors.New("multiple replies to one fixture request")
			}
			if err := json.Unmarshal(frame.Bytes, response); err != nil {
				return err
			}
			sawReply = true
			if receive != nil {
				return receive(frame.Bytes)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if readErr != nil && !sawReply {
			return readErr
		}
	}
	return nil
}
