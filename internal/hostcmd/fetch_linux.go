//go:build linux

package hostcmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/komari-monitor/komari-agent/core/hostops"
)

func fetchHelper(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("fetch-helper", flag.ContinueOnError)
	fs.SetOutput(out)
	manifest := fs.String("manifest", "", "installed service manifest")
	version := fs.String("version", "", "exact signed release tag (no latest or arbitrary URL)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if err := validateReleaseTag(*version); err != nil {
		return err
	}
	if err := requireRoot(); err != nil {
		return err
	}
	unlock, err := acquireHostLock()
	if err != nil {
		return err
	}
	defer unlock()
	m, err := resolveManifest(*manifest)
	if err != nil {
		return err
	}
	trust, err := hostops.ReadTrust(m)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	_, payload, err := cacheHelper(ctx, m, trust, *version, newReleaseClient())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Verified and cached %s %s/%s sha256=%s; no service was installed or changed.\n", payload.Version, payload.OS, payload.Arch, payload.SHA256)
	return err
}

func validateReleaseTag(version string) error {
	if version == "" || len(version) > 100 || strings.Contains(version, "..") {
		return errors.New("an exact release tag is required (release builds embed it; local builds require explicitly staged artifacts)")
	}
	for _, r := range version {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-+", r)) {
			return errors.New("invalid release tag")
		}
	}
	if version == "latest" || version == "." {
		return errors.New("an exact release tag is required")
	}
	return nil
}

func newReleaseClient() *http.Client {
	return &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 || req.URL.Scheme != "https" || req.URL.User != nil || req.URL.Port() != "" && req.URL.Port() != "443" {
			return errors.New("invalid release redirect")
		}
		switch req.URL.Hostname() {
		case "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
			return nil
		}
		return errors.New("release redirected outside the fixed publisher hosts")
	}}
}

func downloadHelper(ctx context.Context, trust *hostops.Trust, version string, client *http.Client) ([]byte, hostops.ReleaseManifest, hostops.ReleasePayload, error) {
	var signed hostops.ReleaseManifest
	var payload hostops.ReleasePayload
	if err := validateReleaseTag(version); err != nil {
		return nil, signed, payload, err
	}
	if len(trust.ReleaseKeys) == 0 {
		return nil, signed, payload, errors.New("pin an independently verified release signing key first")
	}
	name := "komari-agent-rescue-" + runtime.GOOS + "-" + runtime.GOARCH
	base := "https://github.com/r11234567/komari-agent/releases/download/" + version + "/" + name
	download := func(url string, limit int64) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		res, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK || res.ContentLength > limit {
			return nil, errors.New("release asset unavailable or exceeds size limit")
		}
		b, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
		if int64(len(b)) > limit {
			return nil, errors.New("release asset exceeds size limit")
		}
		return b, err
	}
	metadata, err := download(base+".release.json", 1<<20)
	if err != nil {
		return nil, signed, payload, err
	}
	if err = json.Unmarshal(metadata, &signed); err != nil {
		return nil, signed, payload, err
	}
	binary, err := download(base, 256<<20)
	if err != nil {
		return nil, signed, payload, err
	}
	payload, err = hostops.VerifyRelease(trust, signed, binary)
	if err != nil {
		return nil, signed, payload, err
	}
	if payload.Version != version {
		return nil, signed, payload, errors.New("signed release does not match the requested exact tag")
	}
	if len(binary) < 4 || string(binary[:4]) != "\x7fELF" {
		return nil, signed, payload, errors.New("Linux helper must be ELF")
	}
	return binary, signed, payload, nil
}

func helperCache(m *hostops.Manifest) string {
	return filepath.Join("/var/cache/komari", m.ServiceName, "komari-agent-rescue")
}

// cacheHelper is called only by a root CLI holding the host lock. Caller apply
// has already obtained fresh PAM authentication; fetch-helper only stages files.
func cacheHelper(ctx context.Context, m *hostops.Manifest, trust *hostops.Trust, version string, client *http.Client) ([]byte, hostops.ReleasePayload, error) {
	binary, signed, payload, err := downloadHelper(ctx, trust, version, client)
	if err != nil {
		return nil, payload, err
	}
	path := helperCache(m)
	if err = ensureTrustedDir(filepath.Dir(path)); err != nil {
		return nil, payload, err
	}
	if err = hostops.AtomicWrite(path, binary, 0o600); err != nil {
		return nil, payload, err
	}
	if err = hostops.WriteJSON(path+".release.json", signed, 0o644); err != nil {
		return nil, payload, err
	}
	return binary, payload, nil
}

func readHelper(trust *hostops.Trust, artifact, release string) ([]byte, hostops.ReleasePayload, error) {
	var payload hostops.ReleasePayload
	var signed hostops.ReleaseManifest
	if err := hostops.ReadJSON(release, &signed, true); err != nil {
		return nil, payload, err
	}
	if err := hostops.TrustedPath(artifact); err != nil {
		return nil, payload, err
	}
	st, err := os.Stat(artifact)
	if err != nil {
		return nil, payload, err
	}
	if st.Size() > 256<<20 || !st.Mode().IsRegular() {
		return nil, payload, errors.New("invalid helper artifact")
	}
	binary, err := os.ReadFile(artifact)
	if err != nil {
		return nil, payload, err
	}
	payload, err = hostops.VerifyRelease(trust, signed, binary)
	if err != nil {
		return nil, payload, err
	}
	if len(binary) < 4 || string(binary[:4]) != "\x7fELF" {
		return nil, payload, errors.New("Linux helper must be ELF")
	}
	return binary, payload, nil
}

func prepareHelper(ctx context.Context, m *hostops.Manifest, trust *hostops.Trust, artifact, release, version string, client *http.Client, out io.Writer) ([]byte, string, error) {
	if artifact != "" {
		binary, payload, err := readHelper(trust, artifact, release)
		return binary, payload.Version, err
	}
	if err := validateReleaseTag(version); err != nil {
		return nil, "", err
	}
	path := helperCache(m)
	binary, payload, err := readHelper(trust, path, path+".release.json")
	if err == nil && payload.Version == version {
		fmt.Fprintf(out, "Using verified cached rescue release %s.\n", version)
		return binary, payload.Version, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, "", fmt.Errorf("invalid rescue cache: %w", err)
	}
	fmt.Fprintf(out, "Fetching rescue release %s from the fixed publisher for %s/%s; verifying signature and SHA-256 before changing services.\n", version, runtime.GOOS, runtime.GOARCH)
	binary, payload, err = cacheHelper(ctx, m, trust, version, client)
	return binary, payload.Version, err
}
