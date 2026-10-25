//go:build linux

package hostcmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func diagnose(m *hostops.Manifest, p *hostops.Policy, out io.Writer) error {
	if m.InitSystem != "systemd" {
		return errors.New("only Linux systemd installations are supported")
	}
	o, err := observe(m.ServiceName)
	if err != nil {
		return err
	}
	// ExecStart may contain legacy tokens. Never print it or copy it into a
	// world-readable diagnostic document.
	_, err = fmt.Fprintf(out, "service=%s\nservice_user=%s\nmain_pid=%s\npolicy_mode=%d\nhost_actions_ready=%t\n", m.ServiceName, o.User, o.MainPID, p.PrivilegeMode, hostops.HostActionsReady(m))
	return err
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("administrator privileges required; run komari-host from the local root terminal")
	}
	return nil
}
func ensureTrustedDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return errors.New("absolute trusted directory required")
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		if err = ensureTrustedDir(filepath.Dir(dir)); err != nil {
			return err
		}
		if err = os.Mkdir(dir, 0o755); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return hostops.TrustedPath(dir)
}
func verifiedArtifact(path, want string) ([]byte, error) {
	if len(want) != 64 {
		return nil, errors.New("a trusted SHA-256 digest is required")
	}
	if err := hostops.TrustedPath(path); err != nil {
		return nil, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 256<<20 {
		return nil, errors.New("invalid binary size or type")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if !strings.EqualFold(want, hex.EncodeToString(sum[:])) {
		return nil, errors.New("artifact checksum mismatch")
	}
	if len(b) < 4 || string(b[:4]) != "\x7fELF" {
		return nil, errors.New("Linux ELF executable required")
	}
	return b, nil
}

func update(args []string, out io.Writer) (result error) {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(out)
	manifest := fs.String("manifest", "", "service manifest")
	artifact := fs.String("artifact", "", "administrator-staged agent binary")
	digest := fs.String("sha256", "", "trusted release digest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireRoot(); err != nil {
		return err
	}
	unlock, lockErr := acquireHostLock()
	if lockErr != nil {
		return lockErr
	}
	defer unlock()

	m, err := hostops.ReadManifest(*manifest)
	if err != nil {
		return err
	}
	p, err := hostops.ReadPolicy(m)
	if err != nil {
		return err
	}
	if err = noPendingHostTransaction(m); err != nil {
		return err
	}
	if err = rejectPendingSoftwareUpgrade(m); err != nil {
		return err
	}
	if p.HelperInstalled {
		return errors.New("installed rescue requires upgrade-installed-rescue; Agent-only updates are refused")
	}
	if err = hostops.TrustedPath(m.Executable); err != nil {
		return err
	}
	data, err := verifiedArtifact(*artifact, *digest)
	if err != nil {
		return err
	}
	journal := filepath.Join("/var/lib/komari-host", m.ServiceName)
	if err = ensureTrustedDir(journal); err != nil {
		return err
	}
	old, err := os.ReadFile(m.Executable)
	if err != nil {
		return err
	}
	if err = hostops.AtomicWrite(filepath.Join(journal, "agent.previous"), old, 0o700); err != nil {
		return err
	}
	if err = hostops.WriteJSON(filepath.Join(journal, "update.json"), map[string]any{"phase": "prepared", "sha256": *digest, "service": m.ServiceName, "at": time.Now().UTC()}, 0o600); err != nil {
		return err
	}
	// Keep rollback inside the lock if publication or recording fails. An
	// installer must not roll back/restart after a preflight-only refusal, which
	// may be caused by a host transaction starting since its first preflight.
	defer func() {
		if result == nil {
			return
		}
		if restoreErr := hostops.AtomicWrite(m.Executable, old, 0o755); restoreErr != nil {
			result = fmt.Errorf("update failed: %v; Agent rollback failed: %w; backup=%s", result, restoreErr, journal)
			return
		}
		if journalErr := hostops.WriteJSON(filepath.Join(journal, "update.json"), map[string]any{"phase": "restored", "service": m.ServiceName, "at": time.Now().UTC()}, 0o600); journalErr != nil {
			result = fmt.Errorf("update failed: %v; previous Agent restored but journal write failed: %w", result, journalErr)
		}
	}()
	if err = hostops.AtomicWrite(m.Executable, data, 0o755); err != nil {
		return err
	}
	if err = hostops.WriteJSON(filepath.Join(journal, "update.json"), map[string]any{"phase": "binary_replaced", "sha256": *digest, "service": m.ServiceName, "at": time.Now().UTC()}, 0o600); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, "Binary replaced and previous binary backed up. Running daemon unchanged; restart and verify the service explicitly.")
	return err
}

type migrationPlan struct {
	Manifest        hostops.Manifest `json:"manifest"`
	Policy          hostops.Policy   `json:"policy"`
	RestartRequired bool             `json:"restart_required"`
}

func buildMigration(service string, o serviceObservation, deny string) (migrationPlan, []string, error) {
	var plan migrationPlan
	argv, err := parseExecStart(o.ExecStart)
	if err != nil {
		return plan, nil, err
	}
	if deny != "preserve" && deny != "release" {
		return plan, nil, errors.New("specify --legacy-disable=preserve or release after reviewing the local installation; source is unknown")
	}
	dir := filepath.Dir(argv[0])
	mode := int32(2)
	if o.User == "" || o.User == "root" {
		mode = 1
	}
	m := hostops.Manifest{Version: 2, ServiceName: service, ServiceUser: o.User, InitSystem: "systemd", Executable: filepath.Join("/usr/lib/komari", service, "komari-agent"), HostTool: filepath.Join("/usr/lib/komari", service, "komari-host"), HostPolicyFile: filepath.Join(hostops.Registry, service+".policy.json")}
	if m.ServiceUser == "" {
		m.ServiceUser = "root"
	}
	var remoteDisabled, gpu bool
	cleaned := []string{m.Executable}
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		key, val, has := strings.Cut(a, "=")
		switch key {
		case "--runtime-state-file", "--privileged-state-file", "--credentials-file", "--replay-state-file", "--config":
			if !has {
				i++
				if i >= len(argv) {
					return plan, nil, errors.New("missing state path in ExecStart")
				}
				val = argv[i]
			}
			if !filepath.IsAbs(val) {
				if o.WorkingDirectory == "" || !filepath.IsAbs(o.WorkingDirectory) {
					return plan, nil, errors.New("relative state paths require an absolute WorkingDirectory")
				}
				val = filepath.Join(o.WorkingDirectory, val)
			}
			switch key {
			case "--runtime-state-file":
				m.RuntimeStateFile = val
			case "--privileged-state-file":
				m.PrivilegedStateFile = val
			case "--credentials-file":
				m.CredentialsFile = val
			case "--replay-state-file":
				m.ReplayStateFile = val
			case "--config":
				m.ConfigFile = val
			}
			cleaned = append(cleaned, key, val)
		case "--disable-remote-control":
			enabled := true
			if has {
				enabled, err = strconv.ParseBool(val)
				if err != nil {
					return plan, nil, err
				}
			}
			remoteDisabled = enabled
			if deny == "preserve" {
				cleaned = append(cleaned, a)
			}
		case "--enable-gpu", "--gpu":
			gpu = true
			if has {
				gpu, err = strconv.ParseBool(val)
				if err != nil {
					return plan, nil, err
				}
			}
			if key == "--gpu" {
				a = "--enable-gpu"
				if has {
					a += "=" + val
				}
			}
			cleaned = append(cleaned, a)
		default:
			cleaned = append(cleaned, a)
		}
	}
	// Resolve the effective legacy JSON/argv before deciding which existing
	// state files to preserve. A JSON override may differ from the unit argv.
	legacy, err := parseLegacyBootstrap(cleaned)
	if err != nil {
		return plan, nil, err
	}
	remoteDisabled = remoteDisabled || legacy.DisableRemoteControl
	gpu = legacy.EnableGPU
	for target, value := range map[*string]string{
		&m.CredentialsFile: legacy.CredentialsFile, &m.RuntimeStateFile: legacy.RuntimeStateFile,
		&m.PrivilegedStateFile: legacy.PrivilegedStateFile, &m.ReplayStateFile: legacy.ReplayStateFile,
	} {
		if value == "" {
			continue
		}
		if !filepath.IsAbs(value) {
			if !filepath.IsAbs(o.WorkingDirectory) {
				return plan, nil, errors.New("relative legacy JSON state requires absolute WorkingDirectory")
			}
			value = filepath.Join(o.WorkingDirectory, value)
		}
		*target = value
	}
	// Legacy installers used these files; absence is not permission to invent
	// HOME defaults or enroll again. Explicit paths always win.
	for _, entry := range []struct {
		p    *string
		name string
	}{{&m.CredentialsFile, "credentials.json"}, {&m.RuntimeStateFile, "runtime-config.json"}, {&m.PrivilegedStateFile, "privileged.json"}, {&m.ReplayStateFile, "nonces.json"}} {
		if *entry.p == "" {
			candidate := filepath.Join(dir, entry.name)
			if _, err := os.Stat(candidate); err != nil {
				return plan, nil, fmt.Errorf("cannot establish legacy %s path; supply explicit service state paths before migration", entry.name)
			}
			*entry.p = candidate
		}
	}
	p := hostops.Policy{Version: 2, ServiceID: service, PrivilegeMode: mode, AllowRemoteControl: true, AllowWebSSH: true, AllowExecution: true, AllowGPU: true, ForceDenyRemoteControl: remoteDisabled && deny == "preserve", BaselineGPU: gpu, DisableSource: "legacy-unknown-" + deny}
	// Migration never infers grants from old install flags or daemon euid. Existing
	// revision files remain byte-for-byte intact; no new baseline is granted here.
	m.ConfigFile = filepath.Join(hostops.Registry, service+".migration-bootstrap.json")
	plan = migrationPlan{Manifest: m, Policy: p, RestartRequired: true}
	return plan, cleaned, nil
}

func migrate(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(out)
	service := fs.String("service", "", "exact systemd service ID")
	deny := fs.String("legacy-disable", "", "preserve or release; explicitly resolve unknown disable source")
	commit := fs.Bool("commit", false, "write the previewed migration; never restart or enroll")
	artifact := fs.String("agent-artifact", "", "root-owned new agent binary")
	digest := fs.String("sha256", "", "trusted release checksum")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !hostops.ValidService(*service) || strings.HasSuffix(*service, ".service") {
		return errors.New("--service is required; multiple installations are never guessed")
	}
	o, err := observe(*service)
	if err != nil {
		return err
	}
	plan, argv, err := buildMigration(*service, o, *deny)
	if err != nil {
		return err
	}
	if !*commit {
		return hostopsJSON(out, plan)
	}
	if err = requireRoot(); err != nil {
		return err
	}
	unlock, lockErr := acquireHostLock()
	if lockErr != nil {
		return lockErr
	}
	defer unlock()

	binary, err := verifiedArtifact(*artifact, *digest)
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return err
	}
	if err = hostops.TrustedPath(self); err != nil {
		return err
	}
	hostBinary, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	m := &plan.Manifest
	// Capture retired argv as data before replacing the unit. No state snapshot,
	// credential or receipt is rewritten, and the new daemon sees only local flags.
	bootstrap, err := parseLegacyBootstrap(argv)
	if err != nil {
		return err
	}
	bootstrap.ConfigFile = ""
	bootstrap.ServiceManifestFile = ""
	bootstrap.CredentialsFile = m.CredentialsFile
	bootstrap.RuntimeStateFile = m.RuntimeStateFile
	bootstrap.PrivilegedStateFile = m.PrivilegedStateFile
	bootstrap.ReplayStateFile = m.ReplayStateFile
	if *deny == "release" {
		bootstrap.DisableRemoteControl = false
	}
	serviceAccount, err := user.Lookup(m.ServiceUser)
	if err != nil {
		return err
	}
	bootstrapGID, err := strconv.Atoi(serviceAccount.Gid)
	if err != nil {
		return err
	}
	bootstrapData, err := json.MarshalIndent(bootstrap, "", "  ")
	if err != nil {
		return err
	}
	argv = []string{m.Executable, "--config", m.ConfigFile}
	manifestPath := filepath.Join(hostops.Registry, m.ServiceName+".json")
	for _, path := range []string{manifestPath, m.HostPolicyFile, m.ConfigFile, filepath.Join(filepath.Dir(m.Executable), "service-config.json")} {
		if _, err = os.Lstat(path); !os.IsNotExist(err) {
			return fmt.Errorf("migration destination exists or is inaccessible; inspect journal before retry: %s", path)
		}
	}
	journal := filepath.Join("/var/lib/komari-host", m.ServiceName)
	for _, dir := range []string{filepath.Dir(m.Executable), hostops.Registry, journal, filepath.Join("/etc/systemd/system", m.ServiceName+".service.d")} {
		if err = ensureTrustedDir(dir); err != nil {
			return err
		}
	}
	if err = hostops.WriteJSON(filepath.Join(journal, "migration.json"), plan, 0o600); err != nil {
		return err
	}
	// Back up every effective unit source, including drop-ins. Their content may
	// contain secrets, so backups and replacement ExecStart are root-readable only.
	paths, err := splitWords(o.DropInPaths)
	if err != nil {
		return err
	}
	paths = append([]string{o.FragmentPath}, paths...)
	for i, path := range paths {
		if err = hostops.TrustedPath(path); err != nil {
			return err
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if err = hostops.AtomicWrite(filepath.Join(journal, fmt.Sprintf("unit-%d.backup", i)), b, 0o600); err != nil {
			return err
		}
	}
	if err = hostops.AtomicWrite(m.Executable, binary, 0o755); err != nil {
		return err
	}
	if err = hostops.AtomicWrite(m.HostTool, hostBinary, 0o755); err != nil {
		return err
	}
	if err = hostops.AtomicWriteOwned(m.ConfigFile, bootstrapData, 0o640, 0, bootstrapGID); err != nil {
		return err
	}
	if err = hostops.WriteJSON(m.HostPolicyFile, plan.Policy, 0o644); err != nil {
		return err
	}
	if err = hostops.WriteJSON(manifestPath, m, 0o644); err != nil {
		return err
	}
	if err = hostops.WriteJSON(filepath.Join(filepath.Dir(m.Executable), "service-config.json"), m, 0o644); err != nil {
		return err
	}
	var unit strings.Builder
	unit.WriteString("[Service]\nExecStart=\nExecStart=")
	for i, a := range argv {
		if i > 0 {
			unit.WriteByte(' ')
		}
		unit.WriteString(unitQuote(a))
	}
	unit.WriteByte('\n')
	if err = hostops.AtomicWrite(filepath.Join("/etc/systemd/system", m.ServiceName+".service.d", "90-komari-trusted-layout.conf"), []byte(unit.String()), 0o600); err != nil {
		return err
	}
	if _, err = systemctl("daemon-reload"); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Migrated %s. Node identity and all state files preserved. Restart the service explicitly, then run komari-host diagnose --manifest %s.\n", m.ServiceName, manifestPath)
	return err
}
