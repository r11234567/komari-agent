package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	flags_pkg "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/hostops"
)

// The installers put this non-secret manifest beside the real executable.
// Resolving symlinks lets the CLI and service share state regardless of HOME,
// current directory, or the account launching the executable. Standalone
// binaries without a manifest retain the per-user defaults.
type serviceConfig hostops.Manifest

var serviceManifestPath string
var standaloneMode bool

var installedService *serviceConfig

func readServiceConfig(executable string) (*serviceConfig, error) {
	realPath, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return nil, err
	}
	directory := filepath.Dir(realPath)
	path := serviceManifestPath
	if path == "" {
		path = filepath.Join(directory, "service-config.json")
	}
	manifest, err := hostops.ReadManifest(path)
	if os.IsNotExist(err) && serviceManifestPath == "" {
		if !standaloneMode {
			if err := diagnoseMissingManifest(realPath); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read installed service manifest %s: %w", path, err)
	}
	config := serviceConfig(*manifest)

	return &config, nil
}

func (s *serviceConfig) apply(config *flags_pkg.Config) {
	if s == nil {
		return
	}
	for target, value := range map[*string]string{
		&config.CredentialsFile: s.CredentialsFile, &config.RuntimeStateFile: s.RuntimeStateFile,
		&config.PrivilegedStateFile: s.PrivilegedStateFile, &config.ReplayStateFile: s.ReplayStateFile, &config.ConfigFile: s.ConfigFile,
	} {
		if *target == "" {
			*target = value
		}
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func (s *serviceConfig) restartCommand() string {
	name := s.ServiceName
	if name == "" {
		name = "komari-agent"
	}
	switch s.InitSystem {
	case "launchd":
		return "sudo launchctl kickstart -k " + shellQuote("system/com.komari."+name)
	case "windows":
		return "Restart-Service -Name '" + strings.ReplaceAll(name, "'", "''") + "'"
	case "openrc":
		return "sudo rc-service " + shellQuote(name) + " restart"
	case "procd":
		return "sudo " + shellQuote("/etc/init.d/"+name) + " restart"
	case "upstart":
		return "sudo initctl restart " + shellQuote(name)
	default:
		return "sudo systemctl reset-failed " + shellQuote(name) + " && sudo systemctl restart " + shellQuote(name)
	}
}

// Check before contacting the panel: enrolling first and then discovering that
// the service account cannot save the private key leaves an orphaned node.
func prepareLoginStore(path string) error {
	if installedService != nil && runtime.GOOS != "windows" && os.Geteuid() == 0 &&
		installedService.ServiceUser != "" && installedService.ServiceUser != "root" &&
		filepath.Clean(path) == filepath.Clean(installedService.CredentialsFile) {
		return fmt.Errorf("credentials at %s must be written as service user %s; run sudo -u %s komari-agent login --endpoint <panel-address>",
			path, installedService.ServiceUser, shellQuote(installedService.ServiceUser))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return loginStoreError(path, err)
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".komari-login-*")
	if err != nil {
		return loginStoreError(path, err)
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return loginStoreError(path, err)
	}
	return os.Remove(name)
}

func loginStoreError(path string, err error) error {
	hint := "check the directory permissions"
	if installedService != nil {
		if runtime.GOOS == "windows" {
			hint = "run this command in Administrator PowerShell"
		} else {
			hint = "run login as the installed service user: sudo -u " + shellQuote(installedService.ServiceUser) + " komari-agent login --endpoint <panel-address>"
		}
	}
	return fmt.Errorf("cannot write service credentials at %s: %w; %s", path, err, hint)
}
