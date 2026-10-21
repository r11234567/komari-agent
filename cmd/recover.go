package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/komari-monitor/komari-agent/update"
	"github.com/spf13/cobra"
)

const recoverOutputLimit = 64 << 10

var recoverCmd = &cobra.Command{
	Use:   "recover",
	Args:  cobra.NoArgs,
	RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	Short: "Run bounded recovery and diagnostics actions",
	Long:  "Runs one short-lived, auditable recovery action. It never starts an Agent daemon or accepts arbitrary commands.",
}

var recoverVersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the installed Agent version",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return writeRecoverOutput(fmt.Sprintf("version=%s\nplatform=%s/%s\n", update.CurrentVersion, runtime.GOOS, runtime.GOARCH))
	},
}

var recoverVerifyCmd = &cobra.Command{
	Use:   "verify --file PATH --sha256 HEX",
	Short: "Verify a file SHA-256 checksum",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, _ := cmd.Flags().GetString("file")
		expected, _ := cmd.Flags().GetString("sha256")
		if path == "" || expected == "" {
			return fmt.Errorf("--file and --sha256 are required")
		}
		actual, err := fileSHA256(path)
		if err != nil {
			return err
		}
		if !strings.EqualFold(actual, strings.TrimSpace(expected)) {
			return fmt.Errorf("checksum mismatch: got %s", actual)
		}
		return writeRecoverOutput("checksum=verified\n")
	},
}

var recoverDiagnosticsCmd = &cobra.Command{
	Use:   "diagnostics",
	Short: "Print bounded local diagnostic state",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := runtimeStoreForInspection()
		if err != nil {
			return err
		}
		config := store.Current()
		return writeRecoverOutput(fmt.Sprintf(
			"version=%s\nplatform=%s/%s\nconfig_revision=%d\nremote_control_enabled=%t\ndaemon_identity=unavailable (disk inspection)\n",
			update.CurrentVersion, runtime.GOOS, runtime.GOARCH, config.Revision, config.RemoteControlEnabled,
		))
	},
}

func init() {
	recoverVerifyCmd.Flags().String("file", "", "File to verify")
	recoverVerifyCmd.Flags().String("sha256", "", "Expected SHA-256 checksum")
	recoverCmd.AddCommand(recoverVersionCmd, recoverVerifyCmd, recoverDiagnosticsCmd)
	RootCmd.AddCommand(recoverCmd)
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, 1<<30)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeRecoverOutput(value string) error {
	if len(value) > recoverOutputLimit {
		return fmt.Errorf("recovery output exceeds %d bytes", recoverOutputLimit)
	}
	_, err := fmt.Fprint(os.Stdout, value)
	return err
}
