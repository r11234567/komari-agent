package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/komari-monitor/komari-agent/internal/trafficwatch"
	"github.com/spf13/cobra"
)

func init() {
	var path string
	command := &cobra.Command{
		Use:   "traffic-anomaly",
		Short: "Run the opt-in local network traffic anomaly pilot",
		Args:  cobra.NoArgs,
		// The collector has its own operator-controlled configuration and
		// never loads the enrolled Agent's bootstrap files or credentials.
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := trafficwatch.LoadConfig(path)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return trafficwatch.Run(ctx, cfg)
		},
	}
	command.Flags().StringVar(&path, "config-file", "/etc/komari/traffic-anomaly.json", "Local collector configuration")
	RootCmd.AddCommand(command)
}
