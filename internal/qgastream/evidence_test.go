package qgastream

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestEvidenceOnlyRetainsKnownQGAReads(t *testing.T) {
	var evidence Evidence
	var records []Observation
	observe := func(direction Direction, raw string) {
		t.Helper()
		if err := evidence.Observe(direction, Frame{Bytes: []byte(raw)}, func(record Observation) error {
			records = append(records, record)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	observe(Response, `{"return":{"out-data":"frame-before-attachment"}}`)
	observe(Request, `{"execute":"guest-sync-delimited","arguments":{"id":123}}`)
	observe(Response, `{"return":123}`)
	observe(Request, `{"execute":"guest-get-users","id":1}`)
	observe(Response, `{"return":[{"user":"ordinary-lookup"}],"id":1}`)
	observe(Request, `{"execute":"guest-file-read","arguments":{"handle":700},"id":2}`)
	observe(Response, `{"return":{"buf-b64":"unobserved-handle"},"id":2}`)
	omitted := `{"execute":"guest-exec","arguments":{"path":"/bin/test","env":["FIXTURE_SECRET=secret"]},"id":3}`
	observe(Request, omitted)
	observe(Response, `{"return":{"pid":111},"id":3}`)
	observe(Request, `{"execute":"guest-exec-status","arguments":{"pid":111},"id":4}`)
	returned := `{ "return": {"exited":true,"out-data":"dGVzdA=="}, "id":4 }`
	observe(Response, returned)
	observe(Request, `{"execute":"guest-exec-status","arguments":{"pid":111},"id":5}`)
	observe(Response, `{"error":{"class":"GenericError","desc":"already reaped"},"id":5}`)
	if len(records) != 4 {
		t.Fatalf("got %d observations", len(records))
	}
	if !records[0].Omitted || len(records[0].Raw) != 0 || records[0].Digest != sha256.Sum256([]byte(omitted)) {
		t.Fatal("sensitive invocation inputs were not minimized")
	}
	if !bytes.Equal(records[3].Raw, []byte(returned)) || records[3].Digest != sha256.Sum256([]byte(returned)) {
		t.Fatal("original correlated response was modified")
	}
	observe(Response, `{"return":"unpaired"}`)
	if len(records) != 5 || !records[4].Gap || len(records[4].Raw) != 0 {
		t.Fatal("unpaired reply was retained or silently attributed")
	}
}
