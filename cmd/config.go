package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/komari-monitor/komari-agent/core/privileged"
	"github.com/spf13/cobra"
)

var configJSON bool
var configCmd = &cobra.Command{Use: "config", Short: "Inspect the installed service configuration"}
var configShowCmd = &cobra.Command{Use: "show", Short: "Show redacted persisted snapshots (not live daemon attestation)", RunE: func(cmd *cobra.Command, args []string) error { return showConfig(cmd) }}

func showConfig(cmd *cobra.Command) error {
	runtime, err := runtimeStoreForRecovery()
	if err != nil {
		return err
	}
	store, err := privileged.Open(privilegedPath())
	if err != nil {
		return err
	}
	state := store.State()
	// Nonces, tokens, endpoints containing credentials and private keys never
	// appear here. CLI euid is deliberately absent from daemon identity output.
	output := map[string]any{"source": "persisted disk snapshot; live daemon identity unavailable", "runtime": runtime.Current(), "applied_privileged_revision": state.AppliedRevision, "active": state.Active, "pending_revision": state.PendingRevision, "pending": state.Pending, "service": installedService}
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
