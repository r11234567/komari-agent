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
	if fs.NArg() != 0 || *version == "" || len(*version) > 100 || strings.Contains(*version, "..") || strings.ContainsAny(*version, "/\\%?# \t\r\n") {
		return errors.New("an exact release tag is required")
	}
	for _, r := range *version {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-+", r)) {
			return errors.New("invalid release tag")
		}
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
	if len(trust.ReleaseKeys) == 0 {
		return errors.New("pin an independently verified release signing key first")
	}
	client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 || req.URL.Scheme != "https" {
			return errors.New("invalid release redirect")
		}
		switch req.URL.Hostname() {
		case "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
			return nil
		}
		return errors.New("release redirected outside the fixed publisher hosts")
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	name := "komari-agent-rescue-" + runtime.GOOS + "-" + runtime.GOARCH
	base := "https://github.com/r11234567/komari-agent/releases/download/" + *version + "/" + name
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
		return err
	}
	var signed hostops.ReleaseManifest
	if err = json.Unmarshal(metadata, &signed); err != nil {
		return err
	}
	binary, err := download(base, 256<<20)
	if err != nil {
		return err
	}
	payload, err := hostops.VerifyRelease(trust, signed, binary)
	if err != nil {
		return err
	}
	if payload.Version != *version {
		return errors.New("signed release does not match the requested exact tag")
	}
	dir := filepath.Join("/var/cache/komari", m.ServiceName)
	if err = ensureTrustedDir(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, "komari-agent-rescue")
	if err = hostops.AtomicWrite(path, binary, 0o600); err != nil {
		return err
	}
	if err = hostops.WriteJSON(path+".release.json", signed, 0o644); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Verified and cached %s %s/%s sha256=%s; no service was installed or changed.\n", payload.Version, payload.OS, payload.Arch, payload.SHA256)
	return err
}
