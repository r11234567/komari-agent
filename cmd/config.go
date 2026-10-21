package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/core/privileged"
	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"
)

var configJSON bool
var configCmd = &cobra.Command{Use: "config", Short: "Inspect the installed service configuration", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() }}
var configShowCmd = &cobra.Command{Use: "show", Short: "Show redacted persisted snapshots (not live daemon attestation)", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error { return showConfig(cmd) }}

func showConfig(cmd *cobra.Command) error {
	runtime, err := runtimeStoreForInspection()
	if err != nil {
		return err
	}
	store, err := privileged.Open(flags.PrivilegedStateFile)
	if err != nil {
		return err
	}
	state := store.State()
	effective := runtimeconfig.Inspect(flags, runtime, store)
	// Nonces, tokens, endpoints containing credentials and private keys never
	// appear here. CLI euid is deliberately absent from daemon identity output.

	output := map[string]any{
		"source":     "persisted disk snapshots read independently; not a live or atomic daemon observation",
		"queried_at": time.Now().UTC(),
		"runtime":    runtime.Current(), "effective_config_from_disk": effective,
		"outbox_count": len(state.Outbox), "rejected_receipt_count": len(state.RejectedReceipts),
		"applied_privileged_revision": state.AppliedRevision, "active": state.Active,
		"pending_revision": state.PendingRevision, "pending": state.Pending,
		"pending_expires_at": state.PendingExpiry, "privileged_updated_at": state.UpdatedAt,
		"service": installedService,
		"local_config": map[string]any{
			"endpoint": redactedEndpoint(flags.Endpoint), "cf_access_configured": flags.CFAccessClientID != "" && flags.CFAccessClientSecret != "",
			"disable_remote_control": flags.DisableRemoteControl, "disable_auto_update": flags.DisableAutoUpdate,
			"ignore_unsafe_cert": flags.IgnoreUnsafeCert, "prefer_ip_version": flags.PreferIPVersion,
			"custom_dns": flags.CustomDNS, "custom_ipv4": flags.CustomIpv4, "custom_ipv6": flags.CustomIpv6,
			"reconnect_interval": flags.ReconnectInterval, "info_report_interval": flags.InfoReportInterval,
		},
		"runtime_file": snapshotFile(runtimePathForInspection()), "privileged_file": snapshotFile(store.Path()),
		"server_desired_revision": "unavailable offline; pending_revision is only the locally saved candidate",
		"daemon_identity":         "unavailable; the querying user's identity is not daemon identity",
	}
	if installedService != nil {
		m := hostops.Manifest(*installedService)
		p, policyErr := hostops.ReadPolicy(&m)
		output["protected_policy"] = inspectionResult(p, policyErr)
		var record hostops.AppliedRecord
		if err := hostops.ReadJSON(hostops.AppliedPath(&m), &record, true); err != nil {
			output["host_applied_record"] = inspectionResult(nil, err)
		} else {
			var revision configv1.PrivilegedRevision
			if err := proto.Unmarshal(record.Revision, &revision); err != nil {
				output["host_applied_record"] = inspectionResult(nil, err)
			} else {
				output["host_applied_record"] = map[string]any{"revision": revision.Revision, "config_hash": revision.ConfigHash, "approval_generation": revision.ApprovalGeneration, "source": "protected local host record; not server delivery acknowledgement"}
			}
		}
		helper, helperErr := hostops.ReadHelperStatus(&m)
		output["helper_observation"] = inspectionResult(helper, helperErr)
	}

	if configJSON {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(output)
	}
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return err
}
func init() {
	configShowCmd.Flags().BoolVar(&configJSON, "json", false, "Output redacted JSON")
	configCmd.AddCommand(configShowCmd)
	RootCmd.AddCommand(configCmd)
}

// Inspection neither registers a global store nor writes daemon-owned state.
func runtimeStoreForInspection() (*runtimeconfig.Store, error) {
	store, err := runtimeconfig.New(runtimeconfig.FromFlags(flags), flags.RuntimeStateFile)
	if err != nil {
		return nil, fmt.Errorf("open runtime config snapshot: %w", err)
	}
	return store, nil
}

func runtimePathForInspection() string {
	if flags.RuntimeStateFile != "" {
		return flags.RuntimeStateFile
	}
	return runtimeconfig.DefaultStatePath()
}

func snapshotFile(path string) map[string]any {
	info, err := os.Stat(path)
	if err != nil {
		return map[string]any{"path": path, "available": false, "error": err.Error()}
	}
	return map[string]any{"path": path, "available": true, "modified_at": info.ModTime().UTC()}
}

func inspectionResult(value any, err error) map[string]any {
	if err != nil {
		return map[string]any{"available": false, "error": err.Error()}
	}
	return map[string]any{"available": true, "value": value}
}

func redactedEndpoint(value string) string {
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "<configured endpoint; redacted>"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}
