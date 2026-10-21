//go:build linux

package hostcmd

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"

	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/hostops"
)

func resolveManifest(path string) (*hostops.Manifest, error) {
	if path == "" {
		executable, err := os.Executable()
		if err != nil {
			return nil, err
		}
		path = strings.TrimSuffix(executable, "/komari-host") + "/service-config.json"
	}
	m, err := hostops.ReadManifest(path)
	if err != nil {
		return nil, err
	}
	if m.Version != 2 || m.InitSystem != "systemd" || !hostops.ValidService(m.ServiceName) || strings.HasSuffix(m.ServiceName, ".service") {
		return nil, errors.New("trusted Linux systemd service manifest required")
	}
	for _, p := range []string{m.Executable, m.HostTool, m.ManifestPath, m.HostPolicyFile} {
		if err = hostops.TrustedPath(p); err != nil {
			return nil, err
		}
	}
	return m, nil
}
func trust(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("trust", flag.ContinueOnError)
	fs.SetOutput(out)
	manifest := fs.String("manifest", "", "installed service manifest")
	endpoint := fs.String("endpoint", "", "administrator-verified panel HTTPS endpoint")
	agent := fs.String("agent-id", "", "enrolled node UUID")
	key := fs.String("panel-public-key", "", "independently verified base64 Ed25519 panel public key")
	kid := fs.String("panel-key-id", "", "verified panel signing key ID")
	rkey := fs.String("release-public-key", "", "verified base64 Ed25519 release public key")
	rkid := fs.String("release-key-id", "", "verified release signing key ID")
	account := fs.String("service-user", "", "original non-root service account for demotion")
	helper := fs.Bool("allow-rescue-helper", false, "allow separately approved helper installation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
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
	if *account == "" {
		*account = m.ServiceUser
	}
	u, err := user.Lookup(*account)
	if err != nil {
		return err
	}
	if u.Uid == "0" {
		return errors.New("--service-user must name the original non-root account, including on a root installation")
	}
	t := hostops.Trust{Version: 2, AgentID: *agent, Endpoint: strings.TrimRight(*endpoint, "/"), ServiceID: m.ServiceName, ServiceUser: *account, PanelKeys: []credentials.PinnedKey{{Algorithm: 1, KeyID: *kid, Value: *key}}}
	if *rkey != "" || *rkid != "" {
		t.ReleaseKeys = []credentials.PinnedKey{{Algorithm: 1, KeyID: *rkid, Value: *rkey}}
	}
	if err = t.Validate(); err != nil {
		return err
	}
	if _, err = os.Lstat(hostops.TrustPath(m)); !os.IsNotExist(err) {
		return errors.New("host trust already exists; rotate the root-owned trust file after independently verifying the new keys")
	}
	if err = installPAM(); err != nil {
		return err
	}
	p, err := hostops.ReadPolicy(m)
	if err != nil {
		return err
	}
	p.AllowRescueHelper = *helper
	if err = hostops.WriteJSON(m.HostPolicyFile, p, 0o644); err != nil {
		return err
	}
	if err = hostops.WriteJSON(hostops.TrustPath(m), t, 0o644); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, "Pinned independent host trust and dedicated PAM profile. No service identity changed. Install pamtester if missing, then restart the agent to advertise host actions.")
	return err
}
