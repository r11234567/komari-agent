package trafficwatch

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestEvidenceHandoffSkipsRecordsFromBeforeEnrollment(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	now := time.Now().UTC()
	end := now.Add(-time.Minute)
	start := end.Add(-time.Minute)
	event := snapshot{
		ID: uuid.NewString(), Start: start, End: end,
		Sources: []peer{{Address: netip.MustParseAddr("192.0.2.2"), Bytes: 123}},
	}
	name := "event-" + event.ID + ".json"
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o640); err != nil {
		t.Fatal(err)
	}
	for _, enrolled := range []time.Time{start.Add(time.Second), start.Add(-time.Second)} {
		result, err := ReadUpload(root, name, enrolled, now)
		if err != nil || (result == nil) != start.Before(enrolled) {
			t.Fatalf("wrong handoff result for enrollment %s: %v, %v", enrolled, result, err)
		}
		if result != nil && (result.GetIncident().Complete || result.GetIncident().IngressSources[0].Bytes != 123) {
			t.Fatal("initial snapshot or peer count did not survive conversion")
		}
	}
	result, err := ReadUpload(root, name, start.Add(-time.Second), end.Add(snapshotTTL))
	if err != nil || result != nil {
		t.Fatalf("expired record was not skipped: %v, %v", result, err)
	}
	link := "event-" + uuid.NewString() + ".json"
	if err := os.Symlink(name, filepath.Join(dir, link)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadUpload(root, link, start.Add(-time.Second), now); err == nil {
		t.Fatal("followed a symlink in the handoff")
	}
}
