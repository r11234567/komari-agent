package hostcmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/rescue"
)

func setupRescueSSH(args []string, out io.Writer) error {
	options := flag.NewFlagSet("setup-rescue-ssh", flag.ContinueOnError)
	options.SetOutput(out)
	manifestPath := options.String("manifest", "", "installed service manifest")
	checkOnly := options.Bool("check", false, "diagnose compatibility without changing firewall rules or settings")
	nftConfig := options.String("nft-config", "", "persistent nftables entry file (auto-detected by default)")
	network := options.String("interface", "", "public interface when default routes are ambiguous")
	port := options.Uint("port", 0, "local SSH port when more than one listener is present")
	table := options.String("table", "", "inet table when multiple input hooks are present")
	chain := options.String("chain", "", "input chain in the selected inet table")
	if err := options.Parse(args); err != nil {
		return err
	}
	if options.NArg() != 0 || *manifestPath == "" || *port > 65535 || (*table == "") != (*chain == "") {
		return errors.New("provide --manifest, an optional TCP port and both --table and --chain if overriding the input hook")
	}
	if os.Geteuid() != 0 {
		return errors.New("run temporary SSH setup with sudo; apply changes from a direct SSH session")
	}
	m, err := hostops.ReadManifest(*manifestPath)
	if err != nil {
		return err
	}
	if !hostops.ValidService(m.ServiceName) || m.InitSystem != "systemd" {
		return errors.New("temporary SSH setup requires a trusted systemd Agent manifest")
	}
	if _, err := hostops.ReadPolicy(m); err != nil {
		return err
	}
	if err := setRescueSSHCommandEnvironment(); err != nil {
		return err
	}
	planCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	plan, err := rescue.PlanSSHWindow(planCtx, m, rescue.SSHWindowSetupOptions{
		NftConfig: *nftConfig, Interface: *network, Port: uint32(*port), Table: *table, Chain: *chain,
	})
	cancel()
	if err != nil {
		return err
	}
	fmt.Fprintln(out, plan.Description())
	if plan.Configured() {
		fmt.Fprintln(out, "Existing temporary SSH settings and firewall entry point verified.")
		return nil
	}
	if *checkOnly {
		fmt.Fprintln(out, "Found an SSH listener and a compatible firewall entry point. To finish setup, rerun without --check from a direct SSH session.")
		return nil
	}
	if _, err := authenticate(true); err != nil {
		return err
	}
	release, err := acquireHostLock()
	if err != nil {
		return err
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := plan.Apply(ctx); err != nil {
		return err
	}
	fmt.Fprintln(out, "Temporary SSH is configured. The rescue panel will show it on the next helper status update.")
	return nil
}

func setRescueSSHCommandEnvironment() error {
	if err := os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"); err != nil {
		return err
	}
	return os.Setenv("LC_ALL", "C")
}

// apply already holds the host operation lock and completed fresh PAM in a
// direct SSH session. Only prepare the empty entry point after rescue commits.
func configureInstalledRescueSSH(m *hostops.Manifest, operator string, out io.Writer) error {
	if err := confirmAuthSource(true, operator); err != nil {
		return err
	}
	if err := setRescueSSHCommandEnvironment(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	plan, err := rescue.PlanSSHWindow(ctx, m, rescue.SSHWindowSetupOptions{})
	if err != nil {
		return err
	}
	if err := plan.Apply(ctx); err != nil {
		return err
	}
	fmt.Fprintln(out, plan.Description())
	return nil
}
