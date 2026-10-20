package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	flags_pkg "github.com/komari-monitor/komari-agent/cmd/flags"
)

func writeServiceFixture(t *testing.T) (string, string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(dir, "agent")
	if err := os.WriteFile(executable, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(serviceConfig{
		ServiceName: "custom-agent", ServiceUser: "komari", InitSystem: "systemd",
		CredentialsFile: "credentials.json", RuntimeStateFile: "runtime-config.json",
		PrivilegedStateFile: "privileged.json", ReplayStateFile: filepath.Join(dir, "state", "nonces.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "service-config.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, executable
}

func TestServiceStateDoesNotDependOnHomeOrWorkingDirectory(t *testing.T) {
	dir, executable := writeServiceFixture(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("APPDATA", t.TempDir())
	t.Chdir(t.TempDir())
	service, err := readServiceConfig(executable)
	if err != nil {
		t.Fatal(err)
	}
	config := &flags_pkg.Config{}
	service.apply(config)
	if config.CredentialsFile != filepath.Join(dir, "credentials.json") ||
		config.RuntimeStateFile != filepath.Join(dir, "runtime-config.json") ||
		config.PrivilegedStateFile != filepath.Join(dir, "privileged.json") ||
		config.ReplayStateFile != filepath.Join(dir, "state", "nonces.json") {
		t.Fatalf("CLI and daemon must share installation paths, got %+v", config)
	}
}

func TestServiceConfigFollowsExecutableSymlink(t *testing.T) {
	dir, executable := writeServiceFixture(t)
	link := filepath.Join(t.TempDir(), "komari-agent")
	if err := os.Symlink(executable, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	service, err := readServiceConfig(link)
	if err != nil {
		t.Fatal(err)
	}
	if service.CredentialsFile != filepath.Join(dir, "credentials.json") {
		t.Fatalf("symlink selected a different identity: %s", service.CredentialsFile)
	}
}

func TestServiceConfigPreservesExplicitPathsAndEnvironment(t *testing.T) {
	_, executable := writeServiceFixture(t)
	service, err := readServiceConfig(executable)
	if err != nil {
		t.Fatal(err)
	}
	config := &flags_pkg.Config{CredentialsFile: "explicit.json", PrivilegedStateFile: "explicit-privileged.json"}
	service.apply(config)
	if config.CredentialsFile != "explicit.json" || config.PrivilegedStateFile != "explicit-privileged.json" {
		t.Fatal("manifest overrode an explicit CLI flag")
	}
	original := flags
	flags = config
	t.Cleanup(func() { flags = original })
	t.Setenv("AGENT_CREDENTIALS_FILE", "environment.json")
	loadFromEnv()
	if config.CredentialsFile != "environment.json" {
		t.Fatal("environment must retain its existing precedence")
	}
}

func TestServiceConfigMissingVersusBroken(t *testing.T) {
	dir, executable := writeServiceFixture(t)
	path := filepath.Join(dir, "service-config.json")
	if err := os.WriteFile(path, []byte("broken json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readServiceConfig(executable); err == nil {
		t.Fatal("broken installed config must not silently select a per-user identity")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	service, err := readServiceConfig(executable)
	if err != nil || service != nil {
		t.Fatalf("standalone binary must keep per-user defaults: service=%+v, err=%v", service, err)
	}
}

func TestPrepareLoginStoreChecksBeforeEnrollment(t *testing.T) {
	original := installedService
	installedService = nil
	t.Cleanup(func() { installedService = original })
	dir := t.TempDir()
	path := filepath.Join(dir, "new", "credentials.json")
	if err := prepareLoginStore(path); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 0 {
		t.Fatalf("preflight left a credential or temporary file: entries=%v, err=%v", entries, err)
	}
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareLoginStore(filepath.Join(blocker, "credentials.json")); err == nil {
		t.Fatal("unwritable parent must fail before the panel creates an identity")
	}
}

func TestRestartInstructionsMatchServiceManager(t *testing.T) {
	for _, test := range []struct{ init, want string }{
		{"systemd", "systemctl reset-failed 'custom-agent' && sudo systemctl restart 'custom-agent'"},
		{"launchd", "launchctl kickstart -k 'system/com.komari.custom-agent'"},
		{"windows", "Restart-Service -Name 'custom-agent'"},
		{"openrc", "rc-service 'custom-agent' restart"},
		{"procd", "'/etc/init.d/custom-agent' restart"},
	} {
		t.Run(test.init, func(t *testing.T) {
			service := &serviceConfig{ServiceName: "custom-agent", InitSystem: test.init}
			if got := service.restartCommand(); !strings.Contains(got, test.want) {
				t.Fatalf("restart command = %q, want %q", got, test.want)
			}
		})
	}
}
