package flags_pkg

import "testing"

func TestFreshInstallAcceptsOnlyLocalDaemonArguments(t *testing.T) {
	for _, args := range [][]string{{"--interval", "3"}, {"--enable-gpu"}, {"--detailed-gpu"}, {"--memory-include-cache"}, {"--credentials-file", "/tmp/key"}, {"--service-manifest", "/tmp/manifest"}, {"upgrade"}, {"--endpoint"}, {"--endpoint", "https://panel.invalid\nUser=root"}, {"--standalone"}} {
		if err := ValidateInstallArgs(args); err == nil {
			t.Fatalf("installer accepted unsupported argv: %q", args)
		}
	}
	for _, args := range [][]string{{"--endpoint", "https://panel.invalid", "--disable-remote-control"}, {"-e", "https://panel.invalid", "--cf-access-client-id", "id", "--cf-access-client-secret", "secret"}, {"--disable-auto-update", "--prefer-ip-version=4"}} {
		if err := ValidateInstallArgs(args); err != nil {
			t.Fatalf("installer rejected local argv: %q: %v", args, err)
		}
	}
}

func TestLocalJSONRejectsRetiredOnlineKeys(t *testing.T) {
	for _, data := range []string{`{"interval":3}`, `{"EnableGPU":true}`, `{"DETAILED_GPU":true}`, `{"get_ip_addr_from_nic":false}`, `{"memory_include_cache":false}`} {
		if err := DecodeLocalConfig([]byte(data), &Config{}); err == nil {
			t.Fatalf("retired JSON accepted: %s", data)
		}
	}
	c := &Config{}
	if err := DecodeLocalConfig([]byte(`{"endpoint":"https://panel.invalid","disable_remote_control":true}`), c); err != nil || !c.DisableRemoteControl {
		t.Fatalf("local JSON rejected: %v", err)
	}
}
