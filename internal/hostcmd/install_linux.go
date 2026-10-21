//go:build linux

package hostcmd

import (
	"errors"
	"flag"
	"fmt"
	flags "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

func install(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(out)
	service := fs.String("service", "komari-agent", "service ID")
	account := fs.String("user", "komari", "existing service account")
	bindir := fs.String("binary-dir", "/usr/lib/komari/komari-agent", "root-owned binary directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := flags.ValidateInstallArgs(fs.Args()); err != nil {
		return fmt.Errorf("invalid daemon options: %w", err)
	}
	if err := requireRoot(); err != nil {
		return err
	}
	unlock, lockErr := acquireHostLock()
	if lockErr != nil {
		return lockErr
	}
	defer unlock()

	if !hostops.ValidService(*service) || strings.HasSuffix(*service, ".service") || !hostops.ValidService(*account) {
		return errors.New("invalid service or account name")
	}
	manifestPath := filepath.Join(hostops.Registry, *service+".json")
	if _, err := os.Lstat(manifestPath); !os.IsNotExist(err) {
		return errors.New("service already registered or inaccessible; use migrate/update instead of overwriting state")
	}
	for _, path := range []string{filepath.Join(*bindir, "komari-agent"), filepath.Join(*bindir, "komari-host")} {
		if err := hostops.TrustedPath(path); err != nil {
			return err
		}
	}
	u, err := user.Lookup(*account)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	if *account != "root" && uid == 0 {
		return errors.New("service account must not be UID 0")
	}
	stateDir := filepath.Join("/var/lib/komari", *service)
	m := hostops.Manifest{Version: 2, ServiceName: *service, ServiceUser: *account, InitSystem: "systemd", Executable: filepath.Join(*bindir, "komari-agent"), HostTool: filepath.Join(*bindir, "komari-host"), HostPolicyFile: filepath.Join(hostops.Registry, *service+".policy.json"), CredentialsFile: filepath.Join(stateDir, "credentials.json"), RuntimeStateFile: filepath.Join(stateDir, "runtime-config.json"), PrivilegedStateFile: filepath.Join(stateDir, "privileged.json"), ReplayStateFile: filepath.Join(stateDir, "nonces.json")}
	argv := fs.Args()
	mode := int32(2)
	if *account == "root" {
		mode = 1
	}
	p := hostops.Policy{Version: 2, ServiceID: *service, PrivilegeMode: mode, AllowRemoteControl: true, AllowWebSSH: true, AllowExecution: true, AllowGPU: true, DisableSource: "explicit-local-install"}
	for i := 0; i < len(argv); i++ {
		if strings.ContainsAny(argv[i], "\r\n\x00") {
			return errors.New("control characters in installer arguments")
		}
		key, val, has := strings.Cut(argv[i], "=")
		switch key {
		case "--privileged-state-file", "--runtime-state-file", "--credentials-file", "--replay-state-file":
			return errors.New("custom state paths require an explicit reviewed migration, not a fresh installer")
		case "--disable-remote-control":
			p.ForceDenyRemoteControl = true
			if has {
				p.ForceDenyRemoteControl, err = strconv.ParseBool(val)
				if err != nil {
					return err
				}
			}
		}
	}
	argv = append(argv, "--runtime-state-file", m.RuntimeStateFile, "--credentials-file", m.CredentialsFile, "--privileged-state-file", m.PrivilegedStateFile, "--replay-state-file", m.ReplayStateFile)
	// All argument/unit collisions are checked before writing metadata or
	// changing ownership, so a rejected install does not leave a registered node.
	unitPath := filepath.Join("/etc/systemd/system", *service+".service")
	for _, path := range []string{unitPath, m.HostPolicyFile, filepath.Join(*bindir, "service-config.json")} {
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			return fmt.Errorf("installation destination already exists or is inaccessible: %s", path)
		}
	}
	if err = ensureTrustedDir(filepath.Dir(stateDir)); err != nil {
		return err
	}
	// Fresh installs must not reuse or chown an existing directory or symlink.
	if err = os.Mkdir(stateDir, 0o700); err != nil {
		return fmt.Errorf("create fresh state directory: %w", err)
	}
	if err = os.Chown(stateDir, uid, gid); err != nil {
		return err
	}
	for _, dir := range []string{hostops.Registry, "/var/lib/komari-host", "/run/komari"} {
		if err = ensureTrustedDir(dir); err != nil {
			return err
		}
	}
	if err = hostops.WriteJSON(m.HostPolicyFile, p, 0o644); err != nil {
		return err
	}
	if err = hostops.WriteJSON(manifestPath, m, 0o644); err != nil {
		return err
	}
	if err = hostops.WriteJSON(filepath.Join(*bindir, "service-config.json"), m, 0o644); err != nil {
		return err
	}
	var unit strings.Builder
	unit.WriteString("[Unit]\nDescription=Komari Agent\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nExecStart=" + unitQuote(m.Executable))
	for _, a := range argv {
		if strings.ContainsAny(a, "\r\n\x00") {
			return errors.New("control characters in installer arguments")
		}
		unit.WriteByte(' ')
		unit.WriteString(unitQuote(a))
	}
	// WorkingDirectory is a unit path directive, not an ExecStart argv item.
	// Quoting it produces a literal leading quote and systemd rejects the unit.
	// stateDir contains only a fixed prefix and the validated service ID.
	unit.WriteString("\nWorkingDirectory=" + stateDir + "\nUser=" + *account + "\nRestart=on-failure\nRestartSec=5\nAmbientCapabilities=CAP_NET_RAW\nCapabilityBoundingSet=CAP_NET_RAW\nNoNewPrivileges=true\n[Install]\nWantedBy=multi-user.target\n")
	if err = ensureTrustedDir("/etc/systemd/system"); err != nil {
		return err
	}

	if _, err = os.Lstat(unitPath); !os.IsNotExist(err) {
		return errors.New("systemd service already exists; use migrate")
	}
	if err = hostops.AtomicWrite(unitPath, []byte(unit.String()), 0o600); err != nil {
		return err
	}
	if _, err = systemctl("daemon-reload"); err != nil {
		return err
	}
	if _, err = systemctl("enable", *service+".service"); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Installed agent and non-resident host tool; rescue helper is not installed.\nEnroll as %s: sudo -u %s %s login --endpoint <panel-address>\nThen start: sudo systemctl start %s\n", *account, *account, m.Executable, *service)
	return err
}
