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
	if err = noPendingHostTransaction(m); err != nil {
		return err
	}
	p, err := hostops.ReadPolicy(m)
	if err != nil {
		return err
	}
	if !p.HelperInstalled {
		return errors.New("rescue is not registered as installed; upgrades cannot grant installation consent")
	}
	pending, pendingBackup, err := pendingSoftwareUpgrade(m)
	if err != nil {
		return err
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
	var originals [][]byte
	var cfg rescue.Config
	configPath := helperConfig(m)
	if pending != nil {
		originals, err = readUpgradeBackups(m, pending, pendingBackup)
		if err != nil {
			return fmt.Errorf("pending upgrade backups invalid; installed programs unchanged: %w", err)
		}
		configPath = filepath.Join(pendingBackup, "3")
	}
	if err = hostops.ReadJSON(configPath, &cfg, true); err != nil {
		return err
	}
	if err = validateUpgradeConfig(m, t, cfg); err != nil {
		return err
	}
	if err = hostops.TrustedPath(helperUnitPath(m)); err != nil {
		return err
	}
	actual, err := observe(helperUnit(m))
	if err != nil {
		return err
	}
	argv, err := parseExecStart(actual.ExecStart)
	if err != nil || len(argv) != 3 || argv[0] != helperBinary(m) || argv[1] != "--config" || argv[2] != helperConfig(m) || actual.FragmentPath != helperUnitPath(m) || actual.User != "root" || actual.DropInPaths != "" {
		return errors.New("installed rescue unit differs from its protected installation; review locally before upgrade")
	}
	units := []string{m.ServiceName, helperUnit(m)}
	active := make([]bool, len(units))
	paths := upgradePaths(m)
	modes := []os.FileMode{0o755, 0o755, 0o755, 0o600}
	backup := pendingBackup
	previousAttempt := ""
	if pending != nil {
		active, modes = pending.Active, pending.Modes
		// Preserve the exact failed attempt before starting a verified new one.
		// Reuse its original backups, never a mixture of partially installed files.
		previousAttempt = fmt.Sprintf("attempt-%d.json", time.Now().UnixNano())
		previousBytes, readErr := os.ReadFile(filepath.Join(backup, "upgrade.json"))
		if readErr != nil {
			return readErr
		}
		if err = hostops.AtomicWrite(filepath.Join(backup, previousAttempt), previousBytes, 0o600); err != nil {
			return err
		}
		fmt.Fprintf(out, "Recovering pending upgrade phase=%s version=%s using original protected backups; previous attempt=%s/%s\n", pending.Phase, pending.Version, backup, previousAttempt)
	} else {
		for i, unit := range units {
			active[i], err = upgradeServiceActive(unit, i == 1)
			if err != nil {
				return err
			}
		}
		parent := journalDir(m)
		if err = ensureTrustedDir(parent); err != nil {
			return err
		}
		// Read all originals before creating any journal/backup directory.
		originals = make([][]byte, len(paths))
		for i, path := range paths {
			if err = hostops.TrustedPath(path); err != nil {
				return err
			}
			info, statErr := os.Stat(path)
			if statErr != nil || !info.Mode().IsRegular() || info.Size() > 256<<20 {
				return fmt.Errorf("invalid installed upgrade file: %s", path)
			}
			originals[i], err = os.ReadFile(path)
			if err != nil {
				return err
			}
			modes[i] = info.Mode().Perm()
		}
		backup, err = os.MkdirTemp(parent, "upgrade-")
		if err != nil {
			return err
		}
		if err = os.Chmod(backup, 0o700); err != nil {
			return err
		}
		for i, data := range originals {
			if err = hostops.AtomicWrite(filepath.Join(backup, strconv.Itoa(i)), data, 0o600); err != nil {
				return err
			}
		}
	}
	if err = validateUpgradeJournal(m, &softwareUpgrade{Phase: "prepared", Manifest: m.ManifestPath, Paths: paths, Modes: modes, Active: active}); err != nil {
		return err
	}
	writePhase := func(phase string) error {
		return hostops.WriteJSON(filepath.Join(backup, "upgrade.json"), softwareUpgrade{Phase: phase, Version: *version, Manifest: m.ManifestPath, Paths: paths, Modes: modes, Active: active, At: time.Now().UTC(), PreviousAttempt: previousAttempt}, 0o600)
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
