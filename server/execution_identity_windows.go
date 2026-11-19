//go:build windows

package server

import (
	"errors"
	"os"
	"os/exec"
	"strings"

	execv1 "github.com/r11234567/komari-proto/gen/go/komari/exec/v1"
)

const windowsServiceExecOptInEnv = "KOMARI_WINDOWS_ALLOW_SERVICE_EXEC"

var windowsSafeEnvKeys = map[string]struct{}{
	"ALLUSERSPROFILE":        {},
	"APPDATA":                {},
	"COMMONPROGRAMFILES":     {},
	"COMMONPROGRAMFILES(X86)": {},
	"COMMONPROGRAMW6432":     {},
	"COMPUTERNAME":           {},
	"COMSPEC":                {},
	"HOMEDRIVE":              {},
	"HOMEPATH":               {},
	"LOCALAPPDATA":           {},
	"NUMBER_OF_PROCESSORS":   {},
	"OS":                     {},
	"PATH":                   {},
	"PATHEXT":                {},
	"PROCESSOR_ARCHITECTURE": {},
	"PROGRAMDATA":            {},
	"PROGRAMFILES":           {},
	"PROGRAMFILES(X86)":      {},
	"PROGRAMW6432":           {},
	"PSMODULEPATH":           {},
	"PUBLIC":                 {},
	"SYSTEMDRIVE":            {},
	"SYSTEMROOT":             {},
	"TEMP":                   {},
	"TMP":                    {},
	"USERDOMAIN":             {},
	"USERNAME":               {},
	"USERPROFILE":            {},
	"WINDIR":                 {},
}

func configureExecutionIdentity(command *exec.Cmd, spec *execv1.ExecutionSpec) error {
	if spec.RunAsRoot {
		return errors.New("root execution is unavailable on Windows")
	}
	if !strings.EqualFold(strings.TrimSpace(os.Getenv(windowsServiceExecOptInEnv)), "true") {
		return errors.New("Windows remote command execution is disabled unless KOMARI_WINDOWS_ALLOW_SERVICE_EXEC=true explicitly opts into service-account execution")
	}
	command.Dir = spec.WorkingDirectory
	command.Env = minimalWindowsEnvironment()
	return nil
}

// minimalWindowsEnvironment strips daemon secrets (AGENT_TOKEN,
// AGENT_AUTO_DISCOVERY_KEY, Cloudflare Access credentials, etc.) while
// preserving standard OS paths needed by PowerShell and child commands.
func minimalWindowsEnvironment() []string {
	env := make([]string, 0, len(windowsSafeEnvKeys))
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if _, allowed := windowsSafeEnvKeys[strings.ToUpper(key)]; allowed {
			env = append(env, entry)
		}
	}
	return env
}
