package flags_pkg

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/pflag"
)

// RegisterLocalFlags is shared by the daemon and fresh-install validation.
// Online configuration has no public flag or environment override.
func RegisterLocalFlags(fs *pflag.FlagSet, config *Config) {
	fs.StringVarP(&config.Token, "token", "t", "", "API token")
	fs.StringVarP(&config.Endpoint, "endpoint", "e", "", "API endpoint")
	fs.StringVar(&config.AutoDiscoveryKey, "auto-discovery", "", "Auto discovery key for the agent")
	fs.StringVar(&config.ServerName, "server-name", "", "Server display name used for the first auto-discovery registration")
	fs.BoolVar(&config.DisableAutoUpdate, "disable-auto-update", false, "Disable automatic updates")
	fs.BoolVar(&config.DisableRemoteControl, "disable-remote-control", false, "Locally deny all remote control; online approval cannot override this restriction")
	fs.BoolVarP(&config.IgnoreUnsafeCert, "ignore-unsafe-cert", "u", false, "Ignore unsafe certificate errors")
	fs.IntVarP(&config.ReconnectInterval, "reconnect-interval", "c", 5, "Reconnect interval in seconds")
	fs.IntVar(&config.InfoReportInterval, "info-report-interval", 5, "Interval in minutes for reporting basic info")
	fs.StringVar(&config.CustomDNS, "custom-dns", "", "Custom DNS server to use (e.g. 8.8.8.8, 114.114.114.114). By default, the program uses the system DNS resolver.")
	fs.StringVar(&config.CFAccessClientID, "cf-access-client-id", "", "Cloudflare Access service-token Client ID")
	fs.StringVar(&config.CFAccessClientSecret, "cf-access-client-secret", "", "Cloudflare Access service-token Client Secret")
	fs.BoolVar(&config.ShowWarning, "show-warning", false, "Show security warning on Windows, run once as a subprocess")
	fs.StringVar(&config.CustomIpv4, "custom-ipv4", "", "Custom IPv4 address to use")
	fs.StringVar(&config.CustomIpv6, "custom-ipv6", "", "Custom IPv6 address to use")
	fs.StringVar(&config.ConfigFile, "config", "", "Path to the configuration file")
	fs.StringVar(&config.PreferIPVersion, "prefer-ip-version", "", "Prefer IP version for dashboard connections: 4 or 6")
	fs.StringVar(&config.RuntimeStateFile, "runtime-state-file", "", "Path for persisted online runtime configuration snapshots")
	fs.StringVar(&config.PrivilegedStateFile, "privileged-state-file", "", "Path for persisted privileged configuration state")
	fs.StringVar(&config.CredentialsFile, "credentials-file", "", "Path for persisted enrollment credentials")
	fs.StringVar(&config.ReplayStateFile, "replay-state-file", "", "Path for the record of executed signed instructions, which prevents replays")
	fs.ParseErrorsWhitelist.UnknownFlags = false
}

// ValidateInstallArgs runs before any host mutation. Positional arguments and
// paths owned by the installer must not enter the installed daemon argv.
func ValidateInstallArgs(args []string) error {
	fs := pflag.NewFlagSet("agent", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	RegisterLocalFlags(fs, &Config{})
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected daemon argument")
	}
	for _, name := range []string{"runtime-state-file", "privileged-state-file", "credentials-file", "replay-state-file"} {
		if fs.Changed(name) {
			return fmt.Errorf("custom state paths require a reviewed migration")
		}
	}
	for _, arg := range args {
		if strings.ContainsAny(arg, "\r\n\x00") {
			return fmt.Errorf("control characters in installer arguments")
		}
	}
	return nil
}

// DecodeLocalConfig rejects retired public configuration keys. Protected
// migration/host bootstrap files use a separate, administrator-owned read path.
func DecodeLocalConfig(data []byte, config *Config) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	retired := map[string]bool{}
	for _, key := range []string{"interval", "max_retries", "include_nics", "exclude_nics", "include_mountpoints", "month_rotate", "memory_include_cache", "enable_gpu", "detailed_gpu", "get_ip_addr_from_nic", "disable_compression"} {
		retired[key] = true
	}
	for key := range fields {
		// encoding/json matches Go field names case-insensitively as well. Inspect
		// the normalized form too, so alternate spelling cannot revive a retired key.
		normalized := strings.ToLower(strings.ReplaceAll(key, "_", ""))
		for name := range retired {
			if normalized == strings.ReplaceAll(name, "_", "") {
				return fmt.Errorf("configuration key %q was removed; use panel configuration or administrator migration", key)
			}
		}
	}
	return json.Unmarshal(data, config)
}
