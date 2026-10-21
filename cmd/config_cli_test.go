package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/komari-monitor/komari-agent/core/privileged"
	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
)

func TestRetiredCLICommandsAreAbsent(t *testing.T) {
	for _, args := range [][]string{{"upgrade"}, {"update-conf"}, {"rollback"}, {"status", "privileged"}, {"recover", "show-config"}, {"recover", "rollback-config"}} {
		command, remaining, err := RootCmd.Find(args)
		if err == nil && len(remaining) == 0 {
			t.Fatalf("retired command remains registered: %v (%s)", args, command.Name())
		}
	}
	for _, args := range [][]string{{"config", "show"}, {"status"}, {"recover", "diagnostics"}, {"reauth"}} {
		_, remaining, err := RootCmd.Find(args)
		if err != nil || len(remaining) != 0 {
			t.Fatalf("local command missing: %v: %v", args, err)
		}
	}
}

func TestOnlineFlagsAndEnvironmentAreRemoved(t *testing.T) {
	old := *flags
	t.Cleanup(func() { *flags = old })
	for _, name := range []string{"interval", "memory-include-cache", "include-nics", "exclude-nics", "include-mountpoint", "month-rotate", "get-ip-addr-from-nic", "enable-gpu", "detailed-gpu", "max-retries", "disable-compression"} {
		if RootCmd.PersistentFlags().Lookup(name) != nil {
			t.Fatalf("retired flag still registered: %s", name)
		}
	}
	flags.Interval = 3
	flags.EnableGPU = false
	flags.IncludeNics = ""
	t.Setenv("AGENT_INTERVAL", "99")
	t.Setenv("AGENT_ENABLE_GPU", "true")
	t.Setenv("AGENT_INCLUDE_NICS", "unexpected")
	t.Setenv("AGENT_RECONNECT_INTERVAL", "17")
	t.Setenv("AGENT_INFO_REPORT_INTERVAL", "19")
	loadFromEnv()
	if flags.ReconnectInterval != 17 || flags.InfoReportInterval != 19 {
		t.Fatal("retained local environment options stopped working")
	}
	if flags.Interval != 3 || flags.EnableGPU || flags.IncludeNics != "" {
		t.Fatal("retired environment variables changed online settings")
	}
}

func TestConfigShowRedactsSecretsAndDoesNotMutateState(t *testing.T) {
	dir := t.TempDir()
	oldFlags, oldService, oldJSON := *flags, installedService, configJSON
	oldRuntime, oldPriv := runtimeconfig.ActiveStoreForInspection(), privileged.ActiveStore()
	t.Cleanup(func() {
		*flags = oldFlags
		installedService = oldService
		configJSON = oldJSON
		runtimeconfig.SetActive(oldRuntime)
		privileged.SetActive(oldPriv)
		configShowCmd.SetOut(nil)
	})
	installedService = nil
	configJSON = true
	flags.Interval = 3
	flags.Token = "secret-static-token"
	flags.Endpoint = "https://user:secret-password@example.invalid"
	flags.CFAccessClientSecret = "secret-cf-token"
	flags.RuntimeStateFile = filepath.Join(dir, "runtime.json")
	flags.PrivilegedStateFile = filepath.Join(dir, "privileged.json")
	flags.CredentialsFile = filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(flags.CredentialsFile, []byte("secret-private-key"), 0600); err != nil {
		t.Fatal(err)
	}
	// A pending task contains secrets which must never be serialized by the CLI.
	state := privileged.State{PendingRevision: 2, PendingNonce: "secret-nonce", PendingTaskID: "secret-task", ActiveSignedRevision: []byte("secret-signed-authorization")}
	data, _ := json.Marshal(state)
	if err := os.WriteFile(flags.PrivilegedStateFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(flags.PrivilegedStateFile)
	activeRuntime, err := runtimeconfig.New(runtimeconfig.FromFlags(flags), filepath.Join(dir, "other-runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	runtimeconfig.SetActive(activeRuntime)
	var output bytes.Buffer
	configShowCmd.SetOut(&output)
	if err := showConfig(configShowCmd); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-static-token", "secret-password", "secret-cf-token", "secret-private-key", "secret-nonce", "secret-task", "secret-signed-authorization"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("config query exposed %s", secret)
		}
	}
	var parsed map[string]any
	if err := json.Unmarshal(output.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["pending_revision"] != float64(2) || !strings.Contains(parsed["source"].(string), "not a live") {
		t.Fatal("query lost revision or disk-source qualification")
	}
	after, _ := os.ReadFile(flags.PrivilegedStateFile)
	if !bytes.Equal(before, after) {
		t.Fatal("query rewrote privileged state")
	}
	if runtimeconfig.ActiveStoreForInspection() != activeRuntime || privileged.ActiveStore() != oldPriv {
		t.Fatal("query replaced process-wide stores")
	}
	if _, err := os.Stat(flags.RuntimeStateFile); !os.IsNotExist(err) {
		t.Fatal("query created missing runtime state")
	}
}

func TestLocalDenySurvivesBootstrapConfigFalse(t *testing.T) {
	oldFlags, oldService := *flags, installedService
	oldStandalone := standaloneMode
	t.Cleanup(func() { *flags = oldFlags; installedService = oldService; standaloneMode = oldStandalone })
	standaloneMode = true
	flags.DisableRemoteControl = true
	flags.ConfigFile = filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(flags.ConfigFile, []byte(`{"disable_remote_control":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_DISABLE_REMOTE_CONTROL", "false")
	t.Setenv("AGENT_CONFIG_FILE", flags.ConfigFile)
	if err := RootCmd.PersistentPreRunE(configShowCmd, nil); err != nil {
		t.Fatal(err)
	}
	if !flags.DisableRemoteControl {
		t.Fatal("bootstrap false relaxed local force-deny")
	}
}
