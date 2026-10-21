package cmd

import (
	"errors"
	"fmt"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/spf13/cobra"
	"os"
	"os/exec"
)

var upgradeAssumeYes bool

func privilegedPath() string { return flags.PrivilegedStateFile }

var upgradeCmd = &cobra.Command{
	Use: "upgrade", Aliases: []string{"update-conf"},
	Short: "Deprecated: use the administrator-managed komari-host tool",
	RunE: func(cmd *cobra.Command, args []string) error {
		if installedService == nil || installedService.Version != hostops.ManifestVersion || installedService.HostTool == "" {
			return errors.New("installed service requires trusted-layout migration; run komari-host migrate --service <service> --legacy-disable preserve to preview; CLI identity is not daemon identity")
		}
		if err := hostops.TrustedPath(installedService.HostTool); err != nil {
			return err
		}
		if installedService.ManifestPath == "" {
			return errors.New("installed service manifest path is missing")
		}
		fmt.Fprintln(cmd.ErrOrStderr(), "upgrade is deprecated; delegating to the trusted komari-host tool")
		c := exec.CommandContext(cmd.Context(), installedService.HostTool, "apply", "--manifest", installedService.ManifestPath)
		c.Stdin = os.Stdin
		c.Stdout = cmd.OutOrStdout()
		c.Stderr = cmd.ErrOrStderr()
		return c.Run()
	},
}
var rollbackCmd = &cobra.Command{Use: "rollback", Short: "Deprecated privileged rollback entrypoint", RunE: func(*cobra.Command, []string) error {
	return errors.New("privileged state is written only by the daemon; save and approve a new revision in the panel; use root-owned host policy to revoke local permission")
}}
var privilegedStatusCmd = &cobra.Command{Use: "privileged", Short: "Show the installed service's persisted privilege snapshot", RunE: func(cmd *cobra.Command, args []string) error { return showConfig(cmd) }}

func init() {
	upgradeCmd.Flags().BoolVarP(&upgradeAssumeYes, "yes", "y", false, "Deprecated compatibility flag; does not bypass host authentication")
	statusCmd.AddCommand(privilegedStatusCmd)
	RootCmd.AddCommand(upgradeCmd, rollbackCmd)
}
