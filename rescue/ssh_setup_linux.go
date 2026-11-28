package rescue

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/komari-monitor/komari-agent/core/hostops"
	rescuev1 "github.com/r11234567/komari-proto/gen/go/komari/rescue/v1"
)

type SSHWindowSetupOptions struct {
	NftConfig, Interface, Table, Chain string
	Port                               uint32
}

type SSHWindowSetup struct {
	config              sshWindowConfig
	settings, nftConfig string
	configured          bool
}

func (s SSHWindowSetup) Configured() bool { return s.configured }

func (s SSHWindowSetup) Description() string {
	return fmt.Sprintf("Temporary SSH: TCP %d on %s, nftables inet %s/%s", s.config.Port, s.config.Interface, s.config.Table, s.config.Chain)
}

func PlanSSHWindow(ctx context.Context, m *hostops.Manifest, options SSHWindowSetupOptions) (SSHWindowSetup, error) {
	setup := SSHWindowSetup{settings: filepath.Join(filepath.Dir(m.HostPolicyFile), m.ServiceName+".temporary-ssh.json")}
	if existing, err := loadSSHWindowConfig(m); err == nil {
		if options.Port != 0 && options.Port != existing.Port ||
			options.Interface != "" && options.Interface != existing.Interface ||
			options.Table != "" && (options.Table != existing.Table || options.Chain != existing.Chain) {
			return setup, errors.New("an existing temporary SSH setup differs from the requested configuration")
		}
		if _, err := existing.inspect(ctx, true); err != nil {
			return setup, fmt.Errorf("existing temporary SSH setup needs firewall repair: %w", err)
		}
		setup.config, setup.configured = existing, true
		return setup, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return setup, err
	}
	mechanism, err := detectFirewallMechanism(ctx)
	if err != nil {
		return setup, err
	}
	if mechanism != mechanismNftablesSet {
		return setup, fmt.Errorf("%s manages this firewall; automatic temporary SSH requires a native nftables input chain with kernel timeout sets", mechanism)
	}
	if options.Interface == "" {
		devices, err := interfacesForMode(rescuev1.NetworkIsolationMode_NETWORK_ISOLATION_MODE_PUBLIC_INTERFACES)
		if err != nil || len(devices) != 1 {
			return setup, fmt.Errorf("could not select one default interface (%v); provide --interface", devices)
		}
		options.Interface = devices[0]
	}
	if !validSSHWindowInterface(options.Interface) {
		return setup, errors.New("invalid SSH ingress interface")
	}
	port, err := discoverSSHPort(ctx, options.Interface, options.Port)
	if err != nil {
		return setup, err
	}
	ruleset, err := readSSHNftRuleset(ctx)
	if err != nil {
		return setup, err
	}
	table, chain, err := selectSSHInputHook(ruleset, options.Table, options.Chain)
	if err != nil {
		return setup, err
	}
	setup.nftConfig = options.NftConfig
	if setup.nftConfig == "" {
		setup.nftConfig, err = persistentNftConfig(ctx)
		if err != nil {
			return setup, err
		}
	}
	if err := hostops.TrustedPath(setup.nftConfig); err != nil {
		return setup, err
	}
	setup.config = sshWindowConfig{Table: table, Chain: chain, Interface: options.Interface, Port: port}
	return setup, nil
}

func discoverSSHPort(ctx context.Context, device string, explicit uint32) (uint32, error) {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return 0, err
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return 0, err
	}
	var ips []netip.Addr
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().IsGlobalUnicast() {
			ips = append(ips, prefix.Addr().Unmap())
		}
	}
	if len(ips) == 0 {
		return 0, fmt.Errorf("no non-loopback address on %s", device)
	}
	var sockets []sshListenSocket
	var readErr error
	for _, file := range []string{"tcp", "tcp6"} {
		data, err := os.ReadFile(filepath.Join(procRootDirectory(), "net", file))
		if err != nil {
			readErr = errors.Join(readErr, err)
			continue
		}
		sockets = append(sockets, parseSSHListenSockets(string(data))...)
	}
	candidates := make(map[uint32][]netip.Addr)
	for _, socket := range sockets {
		if socket.port == 0 || (explicit != 0 && socket.port != explicit) || (explicit == 0 && !socket.root) {
			continue
		}
		for _, ip := range ips {
			// An IPv6 wildcard can listen for IPv4 too. Confirm each
			// candidate with the actual SSH identification on that address.
			if (socket.address.IsUnspecified() || socket.address == ip) && !slices.Contains(candidates[socket.port], ip) {
				candidates[socket.port] = append(candidates[socket.port], ip)
			}
		}
	}
	if len(candidates) > 32 {
		return 0, errors.New("many TCP listeners found; provide --port")
	}
	var ports []uint32
	for port, ips := range candidates {
		for _, ip := range ips {
			if probeSSHIdentification(ctx, net.JoinHostPort(ip.String(), strconv.FormatUint(uint64(port), 10))) {
				ports = append(ports, port)
				break
			}
		}
	}
	if ctx.Err() != nil {
		return 0, fmt.Errorf("could not confirm SSH listeners within the setup deadline; provide --port: %w", ctx.Err())
	}
	if len(ports) == 1 {
		return ports[0], nil
	}
	if len(ports) > 1 {
		slices.Sort(ports)
		return 0, fmt.Errorf("multiple SSH ports detected on %s (%v); provide --port", device, ports)
	}
	return 0, errors.Join(fmt.Errorf("no SSH listener verified on %s; check sshd and its ListenAddress", device), readErr)
}

func selectSSHInputHook(ruleset sshNftRuleset, table, chain string) (string, string, error) {
	var choices [][2]string
	for _, entry := range ruleset.Entries {
		c := entry.Chain
		if c == nil || c.Family != "inet" || c.Type != "filter" || c.Hook != "input" ||
			c.Table == temporarySSHTable || c.Table == linuxIsolationTable ||
			!sshNftIdentifier.MatchString(c.Table) || !sshNftIdentifier.MatchString(c.Name) {
			continue
		}
		if table == c.Table && chain == c.Name {
			return table, chain, nil
		}
		choices = append(choices, [2]string{c.Table, c.Name})
	}
	if table == "" && len(choices) == 1 {
		return choices[0][0], choices[0][1], nil
	}
	return "", "", fmt.Errorf("could not select an inet nftables input filter (%v); provide --table and --chain", choices)
}

var nftConfigArg = regexp.MustCompile(`(?:^|\s)(?:-f|--file)\s+(/[A-Za-z0-9_/.-]+)(?:\s|$)`)

func persistentNftConfig(ctx context.Context) (string, error) {
	output, _, err := platformCommand(ctx, "systemctl", "show", "nftables.service", "--property=ExecStart", "--value")
	if err == nil {
		args := nftConfigArg.FindAllStringSubmatch(string(output), -1)
		if len(args) == 1 {
			return args[0][1], nil
		}
	}
	return "", errors.New("cannot detect the persistent nftables entry file; provide --nft-config")
}

func (s SSHWindowSetup) Apply(ctx context.Context) error {
	if s.configured {
		return nil
	}
	if _, err := os.Lstat(s.settings); !errors.Is(err, os.ErrNotExist) {
		return errors.New("temporary SSH settings changed during confirmation; rerun setup")
	}
	if err := hostops.TrustedPath(filepath.Dir(s.settings)); err != nil {
		return err
	}
	if err := hostops.TrustedPath(s.nftConfig); err != nil {
		return err
	}
	info, err := os.Stat(s.nftConfig)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return errors.New("nftables entry file is not a regular configuration file of at most 4 MiB")
	}
	original, err := os.ReadFile(s.nftConfig)
	if err != nil {
		return err
	}
	fragment := strings.TrimSuffix(s.settings, ".json") + ".nft"
	if _, err := os.Lstat(fragment); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("existing nftables fragment %s needs local review", fragment)
	}
	include := fmt.Sprintf("\ninclude %s\n", strconv.Quote(fragment))
	batch := s.config.setupCommands()
	if err := checkSSHNft(ctx, batch); err != nil {
		return err
	}
	if err := hostops.AtomicWrite(fragment, []byte(batch), 0o600); err != nil {
		return err
	}
	keepFragment := false
	defer func() {
		if !keepFragment {
			_ = os.Remove(fragment)
		}
	}()
	updated := append(bytes.Clone(original), include...)
	// Validate from a clean ruleset in nft's check-only transaction.
	if err := checkSSHNft(ctx, "flush ruleset\n"+string(updated)); err != nil {
		return fmt.Errorf("persistent configuration cannot restore the SSH hook: %w", err)
	}
	if current, err := os.ReadFile(s.nftConfig); err != nil || !bytes.Equal(current, original) {
		return errors.New("nftables configuration changed during setup; retry after the firewall update")
	}
	if err := hostops.AtomicWrite(s.nftConfig, updated, info.Mode().Perm()); err != nil {
		// A directory sync failure can happen after rename. Retain the
		// fragment if the entry file already references it.
		current, _ := os.ReadFile(s.nftConfig)
		keepFragment = bytes.Equal(current, updated)
		return err
	}
	keepFragment = true
	if err := s.config.apply(ctx, batch); err != nil {
		// A simultaneous firewall reload may have installed the same rules.
		if _, checkErr := s.config.inspect(ctx, true); checkErr != nil {
			if current, readErr := os.ReadFile(s.nftConfig); readErr == nil && bytes.Equal(current, updated) {
				if restoreErr := hostops.AtomicWrite(s.nftConfig, original, info.Mode().Perm()); restoreErr == nil {
					keepFragment = false
				} else {
					return errors.Join(err, restoreErr)
				}
			}
			return err
		}
	}
	if _, err := s.config.inspect(ctx, true); err != nil {
		return err
	}
	return hostops.WriteJSON(s.settings, s.config, 0o600)
}

func (config sshWindowConfig) setupCommands() string {
	var output strings.Builder
	for _, entry := range []struct{ set, kind, protocol string }{
		{sshWindowV4Set, "ipv4_addr", "ip"},
		{sshWindowV6Set, "ipv6_addr", "ip6"},
	} {
		fmt.Fprintf(&output, "add set inet %s %s { type %s; flags timeout; }\n", config.Table, entry.set, entry.kind)
		fmt.Fprintf(&output, "insert rule inet %s %s iifname %q %s saddr @%s tcp dport %d accept\n",
			config.Table, config.Chain, config.Interface, entry.protocol, entry.set, config.Port)
	}
	return output.String()
}

func checkSSHNft(ctx context.Context, config string) error {
	cmd := exec.CommandContext(ctx, "nft", "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(config)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("check nftables file: %s: %w", truncateError(string(output)), err)
	}
	return nil
}
