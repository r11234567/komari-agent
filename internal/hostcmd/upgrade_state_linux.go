//go:build linux

package hostcmd

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/rescue"
)

// Compatible with the original Snapshot journal. Backups always describe the
// pre-upgrade installation, even after a newer signed release retries recovery.
type softwareUpgrade struct {
	Phase           string        `json:"phase"`
	Version         string        `json:"version"`
	Manifest        string        `json:"manifest"`
	Paths           []string      `json:"paths"`
	Modes           []os.FileMode `json:"modes"`
	Active          []bool        `json:"active"`
	At              time.Time     `json:"at"`
	PreviousAttempt string        `json:"previous_attempt,omitempty"`
}

func upgradePaths(m *hostops.Manifest) []string {
	return []string{m.Executable, m.HostTool, helperBinary(m), helperConfig(m)}
}

func noPendingHostTransaction(m *hostops.Manifest) error {
	path := filepath.Join(journalDir(m), "transaction.json")
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		if err != nil {
			return err
		}
		return fmt.Errorf("host authorization transaction is pending; reconcile with %s or restore with %s before upgrading; no installed files changed", hostRecoveryCommand(m, "resume"), hostRecoveryCommand(m, "restore"))
	}
	return nil
}

func pendingSoftwareUpgrade(m *hostops.Manifest) (*softwareUpgrade, string, error) {
	paths, err := filepath.Glob(filepath.Join(journalDir(m), "upgrade-*", "upgrade.json"))
	if err != nil {
		return nil, "", err
	}
	var pending *softwareUpgrade
	var backup string
	for _, path := range paths {
		var state softwareUpgrade
		if err := hostops.ReadJSON(path, &state, true); err != nil {
			return nil, "", err
		}
		if state.Phase == "completed" || state.Phase == "restored" {
			continue
		}
		if err := validateUpgradeJournal(m, &state); err != nil {
			return nil, "", fmt.Errorf("unsafe pending upgrade %s: %w", path, err)
		}
		if pending != nil {
			return nil, "", errors.New("multiple pending software upgrades; review protected backups locally before further changes")
		}
		pending, backup = &state, filepath.Dir(path)
	}
	return pending, backup, nil
}

func validateUpgradeJournal(m *hostops.Manifest, s *softwareUpgrade) error {
	switch s.Phase {
	case "prepared", "replacing", "restore_failed":
	default:
		return fmt.Errorf("unknown upgrade phase %q", s.Phase)
	}
	if s.Manifest != m.ManifestPath || !slices.Equal(s.Paths, upgradePaths(m)) || len(s.Modes) != 4 || len(s.Active) != 2 {
		return errors.New("journal does not bind this installation's manifest, paths, modes and service states")
	}
	for i, mode := range s.Modes {
		if mode & ^os.FileMode(0o777) != 0 || mode&0o022 != 0 || mode&0o400 == 0 || (i < 3 && mode&0o111 == 0) || (i == 3 && mode&0o077 != 0) {
			return errors.New("journal contains unsafe backup permissions")
		}
	}
	return nil
}

func readUpgradeBackups(m *hostops.Manifest, s *softwareUpgrade, dir string) ([][]byte, error) {
	if err := validateUpgradeJournal(m, s); err != nil {
		return nil, err
	}
	originals := make([][]byte, 4)
	for i := range originals {
		path := filepath.Join(dir, strconv.Itoa(i))
		if err := hostops.TrustedPath(path); err != nil {
			return nil, err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() > 256<<20 {
			return nil, fmt.Errorf("invalid protected upgrade backup: %s", path)
		}
		originals[i], err = os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if i < 3 && !bytes.HasPrefix(originals[i], []byte("\x7fELF")) {
			return nil, fmt.Errorf("protected executable backup is not an ELF: %s", path)
		}
	}
	return originals, nil
}

func validateUpgradeConfig(m *hostops.Manifest, t *hostops.Trust, cfg rescue.Config) error {
	helperManifest, err := resolveManifest(cfg.HostManifest)
	if err != nil {
		return fmt.Errorf("installed rescue manifest: %w", err)
	}
	helperManifest.ManifestPath = m.ManifestPath
	if *helperManifest != *m || cfg.CredentialsFile != m.CredentialsFile || cfg.AgentID != t.AgentID || cfg.Endpoint != t.Endpoint || cfg.Action.ServiceName != m.ServiceName || cfg.Action.AgentPath != m.Executable {
		return errors.New("installed rescue configuration belongs to a different installation")
	}
	return nil
}

// Read-only compatibility/transaction gate called on the staged target Host,
// before an old installed Host or installer can modify any installed program.
func checkUpgrade(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("check-upgrade", flag.ContinueOnError)
	fs.SetOutput(out)
	manifest := fs.String("manifest", "", "installed service manifest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected preflight arguments")
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
	pending, backup, err := pendingSoftwareUpgrade(m)
	if err != nil {
		return err
	}
	if pending != nil {
		if !p.HelperInstalled {
			return errors.New("pending rescue upgrade conflicts with current installation policy; restore the host transaction first")
		}
		if _, err = readUpgradeBackups(m, pending, backup); err != nil {
			return fmt.Errorf("pending upgrade backups incomplete; no installed files changed: %w", err)
		}
		fmt.Fprintf(out, "Pending software upgrade phase=%s; the verified coordinated target will recover from protected backups=%s\n", pending.Phase, backup)
	}
	_, err = fmt.Fprintln(out, "Upgrade preflight passed; software updates do not approve pending privileged configuration.")
	return err
}

func rejectPendingSoftwareUpgrade(m *hostops.Manifest) error {
	state, backup, err := pendingSoftwareUpgrade(m)
	if err != nil {
		return err
	}
	if state != nil {
		return fmt.Errorf("software upgrade interrupted (phase=%s); rerun the current Linux installer with a signed rescue-capable release to recover %s before applying host changes", state.Phase, backup)
	}
	return nil
}

func upgradeServiceActive(unit string, helper bool) (bool, error) {
	value, err := systemctl("show", unit, "--property=ActiveState", "--value")
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(value) {
	case "active":
		return true, nil
	case "inactive", "failed":
		return false, nil
	case "activating":
		if helper {
			sub, err := systemctl("show", unit, "--property=SubState", "--value")
			if err != nil {
				return false, err
			}
			if strings.TrimSpace(sub) == "auto-restart" {
				return true, nil
			}
		}
	}
	return false, fmt.Errorf("service %s is transitioning; retry after it settles", unit)
}
