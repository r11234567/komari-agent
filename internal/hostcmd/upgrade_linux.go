//go:build linux

package hostcmd

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/rescue"
)

// upgradeInstalledRescue updates an existing installation, never authorizes or
// installs rescue. The installer stages one exact release before calling it.
// Hold the same lock as apply/restore for the entire replacement and rollback.
func upgradeInstalledRescue(args []string, out io.Writer) (result error) {
	fs := flag.NewFlagSet("upgrade-installed-rescue", flag.ContinueOnError)
	fs.SetOutput(out)
	manifest := fs.String("manifest", "", "installed service manifest")
	agent := fs.String("agent-artifact", "", "staged Agent ELF")
	agentHash := fs.String("agent-sha256", "", "Agent SHA256 from the selected release")
	host := fs.String("host-artifact", "", "staged Host ELF")
	hostHash := fs.String("host-sha256", "", "Host SHA256 from the selected release")
	helper := fs.String("helper-artifact", "", "staged rescue ELF")
	signature := fs.String("release-manifest", "", "publisher-signed rescue metadata")
	version := fs.String("version", "", "exact target release tag")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected upgrade arguments")
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
	if err = rejectPendingSoftwareUpgrade(m); err != nil {
		return err
	}
	p, err := hostops.ReadPolicy(m)
	if err != nil {
		return err
	}
	if !p.HelperInstalled {
		return errors.New("rescue is not registered as installed; upgrades cannot grant installation consent")
	}
	if _, err := os.Lstat(filepath.Join(journalDir(m), "transaction.json")); !os.IsNotExist(err) {
		return errors.New("finish or restore the pending host transaction before upgrading")
	}
	t, err := hostops.ReadTrust(m)
	if err != nil {
		return err
	}
	agentBytes, err := verifiedArtifact(*agent, *agentHash)
	if err != nil {
		return fmt.Errorf("Agent preflight: %w", err)
	}
	hostBytes, err := verifiedArtifact(*host, *hostHash)
	if err != nil {
		return fmt.Errorf("Host preflight: %w", err)
	}
	helperBytes, payload, err := readHelper(t, *helper, *signature)
	if err != nil {
		return fmt.Errorf("rescue preflight; installed programs unchanged: %w", err)
	}
	if payload.Version != *version {
		return errors.New("signed rescue version differs from the selected Agent/Host release")
	}
	if ReleaseVersion != "" && ReleaseVersion != *version {
		return errors.New("target Host release differs from the selected upgrade version")
	}
	var cfg rescue.Config
	if err = hostops.ReadJSON(helperConfig(m), &cfg, true); err != nil {
		return err
	}
	helperManifest, err := resolveManifest(cfg.HostManifest)
	if err != nil {
		return fmt.Errorf("installed rescue manifest: %w", err)
	}
	helperManifest.ManifestPath = m.ManifestPath
	if *helperManifest != *m || cfg.AgentID != t.AgentID || cfg.Endpoint != t.Endpoint || cfg.Action.ServiceName != m.ServiceName || cfg.Action.AgentPath != m.Executable {
		return errors.New("installed rescue configuration belongs to a different installation")
	}
	if err = hostops.TrustedPath(helperUnitPath(m)); err != nil {
		return err
	}
	actual, err := observe(helperUnit(m))
	if err != nil {
		return err
	}
	argv, err := parseExecStart(actual.ExecStart)
	if err != nil || len(argv) != 3 || argv[0] != helperBinary(m) || argv[1] != "--config" || argv[2] != helperConfig(m) || actual.FragmentPath != helperUnitPath(m) || actual.User != "root" {
		return errors.New("installed rescue unit differs from its protected installation; review locally before upgrade")
	}
	units := []string{m.ServiceName, helperUnit(m)}
	active := make([]bool, len(units))
	for i, unit := range units {
		state, err := systemctl("show", unit, "--property=ActiveState", "--value")
		if err != nil {
			return err
		}
		switch strings.TrimSpace(state) {
		case "active":
			active[i] = true
		case "inactive", "failed":
		default:
			return fmt.Errorf("service %s is transitioning; retry after it settles", unit)
		}
	}
	parent := journalDir(m)
	if err = ensureTrustedDir(parent); err != nil {
		return err
	}
	backup, err := os.MkdirTemp(parent, "upgrade-")
	if err != nil {
		return err
	}
	if err = os.Chmod(backup, 0o700); err != nil {
		return err
	}
	paths := []string{m.Executable, m.HostTool, helperBinary(m), helperConfig(m)}
	modes := []os.FileMode{0o755, 0o755, 0o755, 0o600}
	originals := make([][]byte, len(paths))
	for i, path := range paths {
		if err = hostops.TrustedPath(path); err != nil {
			return err
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<20 {
			return fmt.Errorf("invalid installed upgrade file: %s", path)
		}
		originals[i], err = os.ReadFile(path)
		if err != nil {
			return err
		}
		modes[i] = info.Mode().Perm()
		if err = hostops.AtomicWrite(filepath.Join(backup, strconv.Itoa(i)), originals[i], 0o600); err != nil {
			return err
		}
	}
	writePhase := func(phase string) error {
		return hostops.WriteJSON(filepath.Join(backup, "upgrade.json"), map[string]any{"phase": phase, "version": *version, "manifest": m.ManifestPath, "paths": paths, "modes": modes, "active": active, "at": time.Now().UTC()}, 0o600)
	}
	if err = writePhase("prepared"); err != nil {
		return err
	}
	fmt.Fprintf(out, "Verified signed rescue release %s. Upgrading Agent, Host and installed rescue together; backups=%s\n", *version, backup)
	defer func() {
		if result == nil {
			return
		}
		var failures []error
		for _, unit := range units {
			if _, err := systemctl("stop", unit); err != nil {
				failures = append(failures, err)
			}
		}
		for i, path := range paths {
			if err := hostops.AtomicWrite(path, originals[i], modes[i]); err != nil {
				failures = append(failures, err)
			}
		}
		if len(failures) == 0 {
			for i, unit := range units {
				if active[i] {
					if err := restartReviewedService(unit); err != nil {
						failures = append(failures, err)
					} else {
						want := m.Executable
						if i == 1 {
							want = helperBinary(m)
						}
						if err := verifyUpgradeService(unit, want); err != nil {
							failures = append(failures, err)
						}
					}
				}
			}
		}
		if len(failures) != 0 {
			_ = writePhase("restore_failed")
			result = fmt.Errorf("upgrade failed: %v; rollback incomplete: %w; protected backups=%s", result, errors.Join(failures...), backup)
		} else {
			_ = writePhase("restored")
			result = fmt.Errorf("upgrade failed; previous Agent, Host, rescue and configuration restored: %w; backups=%s", result, backup)
		}
	}()
	for _, unit := range units {
		if _, err = systemctl("stop", unit); err != nil {
			return err
		}
	}
	if err = writePhase("replacing"); err != nil {
		return err
	}
	for i, data := range [][]byte{agentBytes, hostBytes, helperBytes} {
		if err = hostops.AtomicWrite(paths[i], data, modes[i]); err != nil {
			return err
		}
	}
	cfg.Version = *version
	if err = hostops.WriteJSON(helperConfig(m), cfg, modes[3]); err != nil {
		return err
	}
	for i, unit := range units {
		if !active[i] {
			continue
		}
		if err = restartReviewedService(unit); err != nil {
			return err
		}
		want := m.Executable
		if i == 1 {
			want = helperBinary(m)
		}
		if err = verifyUpgradeService(unit, want); err != nil {
			return err
		}
	}
	if err = writePhase("completed"); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Agent, Host and installed rescue upgraded to %s; identities, authorization, credentials and previous active/stopped states retained.\n", *version)
	return err
}

func verifyUpgradeService(unit, executable string) error {
	o, err := observe(unit)
	if err != nil {
		return err
	}
	pid := o.MainPID
	for observation := 0; observation < 5; observation++ {
		time.Sleep(time.Second)
		o, err = observe(unit)
		exe, exeErr := os.Readlink("/proc/" + o.MainPID + "/exe")
		if err != nil || exeErr != nil || pid == "0" || pid == "" || o.MainPID != pid || exe != executable {
			return fmt.Errorf("service %s failed upgrade process/executable health checks", unit)
		}
	}
	return nil
}

func rejectPendingSoftwareUpgrade(m *hostops.Manifest) error {
	paths, err := filepath.Glob(filepath.Join(journalDir(m), "upgrade-*", "upgrade.json"))
	if err != nil {
		return err
	}
	for _, path := range paths {
		var state map[string]any
		if err := hostops.ReadJSON(path, &state, true); err != nil {
			return err
		}
		if state["phase"] != "completed" && state["phase"] != "restored" {
			return fmt.Errorf("software upgrade interrupted; review and restore protected backups at %s before further host changes", filepath.Dir(path))
		}
	}
	return nil
}
