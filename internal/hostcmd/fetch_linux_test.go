//go:build linux

package hostcmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/core/privileged"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
)

type releaseTransport func(*http.Request) (*http.Response, error)

func (f releaseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func helperReleaseFixture(t *testing.T) (*hostops.Trust, []byte, []byte) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binary := []byte("\x7fELF publisher fixture")
	metadata, err := json.Marshal(testRelease(t, key, binary))
	if err != nil {
		t.Fatal(err)
	}
	trust := &hostops.Trust{ServiceUser: "komari", ReleaseKeys: []credentials.PinnedKey{{Algorithm: 1, KeyID: "stage6", Value: base64.StdEncoding.EncodeToString(pub)}}}
	return trust, binary, metadata
}

func releaseFixtureClient(t *testing.T, binary, metadata []byte, calls *int) *http.Client {
	t.Helper()
	return &http.Client{Transport: releaseTransport(func(r *http.Request) (*http.Response, error) {
		(*calls)++
		base := "https://github.com/r11234567/komari-agent/releases/download/ci-stage6/komari-agent-rescue-" + runtime.GOOS + "-" + runtime.GOARCH
		if r.URL.String() != base && r.URL.String() != base+".release.json" {
			t.Errorf("unexpected publisher URL: %s", r.URL)
		}
		if len(r.Header) != 0 {
			t.Errorf("release fetch leaked headers: %v", r.Header)
		}
		data := binary
		if strings.HasSuffix(r.URL.Path, ".release.json") {
			data = metadata
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), ContentLength: int64(len(data)), Header: make(http.Header)}, nil
	})}
}

func TestRescueDownloadVerifiesFixedPublisherAndSignature(t *testing.T) {
	trust, binary, metadata := helperReleaseFixture(t)
	calls := 0
	got, _, payload, err := downloadHelper(context.Background(), trust, "ci-stage6", releaseFixtureClient(t, binary, metadata, &calls))
	if err != nil || !bytes.Equal(got, binary) || payload.Version != "ci-stage6" || calls != 2 {
		t.Fatalf("download: version=%s calls=%d error=%v", payload.Version, calls, err)
	}
	for _, tc := range []struct {
		name             string
		binary, metadata []byte
	}{
		{"tampered binary", append(append([]byte{}, binary...), byte('!')), metadata},
		{"invalid manifest", binary, []byte(`{"payload":"broken"}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			if _, _, _, err := downloadHelper(context.Background(), trust, "ci-stage6", releaseFixtureClient(t, tc.binary, tc.metadata, &calls)); err == nil {
				t.Fatal("unverified download accepted")
			}
		})
	}
	other, _, _ := helperReleaseFixture(t)
	if _, _, _, err = downloadHelper(context.Background(), other, "ci-stage6", releaseFixtureClient(t, binary, metadata, &calls)); err == nil {
		t.Fatal("wrong publisher key accepted")
	}
	for _, tc := range []struct {
		name         string
		status       int
		length       int64
		transportErr error
	}{
		{"404", 404, 0, nil}, {"oversized metadata", 200, 1 << 21, nil}, {"network failure", 0, 0, errors.New("fixture network unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: releaseTransport(func(*http.Request) (*http.Response, error) {
				if tc.transportErr != nil {
					return nil, tc.transportErr
				}
				return &http.Response{StatusCode: tc.status, ContentLength: tc.length, Body: io.NopCloser(strings.NewReader(""))}, nil
			})}
			if _, _, _, err := downloadHelper(context.Background(), trust, "ci-stage6", client); err == nil {
				t.Fatal("unavailable release accepted")
			}
		})
	}
}

func TestRescueDownloadRejectsMutableTagsAndUntrustedRedirects(t *testing.T) {
	for _, tag := range []string{"", "latest", ".", "../main", "https://host/x", "1.2.86?x", "1.2.86\n"} {
		if validateReleaseTag(tag) == nil {
			t.Errorf("unsafe release tag accepted: %q", tag)
		}
	}
	client := newReleaseClient()
	for _, raw := range []string{"http://github.com/x", "https://attacker.invalid/x", "https://github.com.attacker.invalid/x", "https://github.com:8443/x", "https://user:secret@github.com/x"} {
		u, _ := url.Parse(raw)
		if client.CheckRedirect(&http.Request{URL: u}, nil) == nil {
			t.Errorf("unsafe redirect accepted: %s", u.Host)
		}
	}
	u, _ := url.Parse("https://release-assets.githubusercontent.com/x")
	if err := client.CheckRedirect(&http.Request{URL: u}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestRescueInstallConsentDoesNotChangeDaemonIdentity(t *testing.T) {
	trust, _, _ := helperReleaseFixture(t)
	p := &hostops.Policy{PrivilegeMode: 2}
	settings := privileged.Settings{RequiredPrivilegeMode: 2, RescueHelperEnabled: true}
	r := &configv1.PrivilegedRevision{Privileged: settings.Proto(), Authorization: &hostv1.HostAuthorization{TargetPrivilegeMode: 2, Actions: []hostv1.HostAction{2}}}
	if err := validateActions(nil, p, trust, r, serviceObservation{User: "komari"}); err != nil {
		t.Fatal("first install should await PAM rather than prior consent:", err)
	}
	if p.AllowRescueHelper || p.PrivilegeMode != 2 {
		t.Fatal("validation changed local consent or Agent identity")
	}
	p.ForceDenyRescueHelper = true
	if err := validateActions(nil, p, trust, r, serviceObservation{User: "komari"}); err == nil {
		t.Fatal("local force deny bypassed")
	}
	p.ForceDenyRescueHelper = false
	trust.ReleaseKeys = nil
	if err := validateActions(nil, p, trust, r, serviceObservation{User: "komari"}); err == nil {
		t.Fatal("missing publisher trust accepted")
	}
}

func TestHostRescuePrepareOnDemand(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("root cache is tested only on disposable CI")
	}
	service := os.Getenv("KOMARI_STAGE6_SERVICE") + "-fetch"
	if !hostops.ValidService(service) || service == "-fetch" {
		t.Fatal("isolated CI service required")
	}
	m := &hostops.Manifest{ServiceName: service}
	path := helperCache(m)
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(path)) })
	trust, binary, metadata := helperReleaseFixture(t)
	calls := 0
	client := releaseFixtureClient(t, binary, metadata, &calls)
	got, version, err := prepareHelper(context.Background(), m, trust, "", "", "ci-stage6", client, os.Stdout)
	if err != nil || version != "ci-stage6" || !bytes.Equal(got, binary) || calls != 2 {
		t.Fatalf("automatic first download: calls=%d version=%s error=%v", calls, version, err)
	}
	if _, _, err = prepareHelper(context.Background(), m, trust, "", "", "ci-stage6", client, os.Stdout); err != nil || calls != 2 {
		t.Fatalf("verified cache should avoid download: calls=%d error=%v", calls, err)
	}
	if err = hostops.AtomicWrite(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = prepareHelper(context.Background(), m, trust, "", "", "ci-stage6", client, os.Stdout); err == nil || calls != 2 {
		t.Fatal("tampered cache accepted or fetched without diagnosing corruption")
	}
}
