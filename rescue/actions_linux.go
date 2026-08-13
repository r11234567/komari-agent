//go:build linux

package rescue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	rescuev1 "github.com/r11234567/komari-proto/gen/go/komari/rescue/v1"
)

const linuxIsolationTable = "komari_rescue"

type isolationState struct {
	Mode       rescuev1.NetworkIsolationMode `json:"mode"`
	Interfaces []string                      `json:"interfaces,omitempty"`
	AppliedAt  time.Time                     `json:"applied_at"`
}

func isPrivileged() bool { return os.Geteuid() == 0 }

func platformCommand(ctx context.Context, name string, arguments ...string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	var stdout, stderr strings.Builder
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	return []byte(stdout.String()), []byte(stderr.String()), err
}

func machineDiagnostics(ctx context.Context) (ActionResult, error) {
	checks := [][]string{
		{"uname", "-a"}, {"uptime"}, {"free", "-h"}, {"df", "-h"},
		{"ip", "-brief", "address"}, {"ip", "route", "show"},
		{"systemctl", "--failed", "--no-pager", "--plain"},
	}
	var output strings.Builder
	for _, check := range checks {
		output.WriteString("$ " + strings.Join(check, " ") + "\n")
		stdout, stderr, err := platformCommand(ctx, check[0], check[1:]...)
		output.Write(stdout)
		output.Write(stderr)
		if err != nil {
			output.WriteString("error=" + err.Error() + "\n")
		}
		output.WriteByte('\n')
	}
	return ActionResult{Stdout: limitBytes([]byte(output.String()), maximumActionOutput)}, nil
}

func preparePowerAction(_ ActionConfig, reboot bool) (ActionResult, error) {
	if !isPrivileged() {
		return ActionResult{}, errors.New("machine power control requires a privileged rescue helper")
	}
	verb := "poweroff"
	message := "shutdown"
	if reboot {
		verb, message = "reboot", "reboot"
	}
	return ActionResult{
		Stdout: []byte("machine_" + message + "=scheduled\n"),
		AfterReport: func(context.Context) error {
			time.Sleep(2 * time.Second)
			return exec.Command("systemctl", verb).Start()
		},
	}, nil
}

func prepareAgentRestart(config ActionConfig) (ActionResult, error) {
	if !isPrivileged() {
		return ActionResult{}, errors.New("restarting the Agent requires a privileged rescue helper")
	}
	service := strings.TrimSpace(config.ServiceName)
	if service == "" || strings.ContainsAny(service, "/\\\x00\n\r") {
		return ActionResult{}, errors.New("invalid Agent service name")
	}
	return ActionResult{
		Stdout: []byte("online_config_rollback=accepted\nagent_restart=scheduled\n"),
		AfterReport: func(context.Context) error {
			time.Sleep(2 * time.Second)
			return exec.Command("systemctl", "restart", service+".service").Start()
		},
	}, nil
}

func prepareInterfaceIsolation(config ActionConfig, mode rescuev1.NetworkIsolationMode) (ActionResult, error) {
	if !isPrivileged() {
		return ActionResult{}, errors.New("network isolation requires a privileged rescue helper")
	}
	interfaces, err := interfacesForMode(mode)
	if err != nil {
		return ActionResult{}, err
	}
	script := interfaceIsolationRules(interfaces)
	return ActionResult{
		Stdout: []byte(fmt.Sprintf("network_isolation=scheduled\ninterfaces=%s\n", strings.Join(interfaces, ","))),
		AfterReport: func(ctx context.Context) error {
			time.Sleep(2 * time.Second)
			state := isolationState{Mode: mode, Interfaces: interfaces, AppliedAt: time.Now().UTC()}
			if err := saveIsolationState(config, state); err != nil {
				return fmt.Errorf("save network isolation state: %w", err)
			}
			if err := applyNftScript(ctx, config, script); err != nil {
				_ = os.Remove(isolationPath(config))
				return err
			}
			return nil
		},
	}, nil
}

func prepareControlPlaneIsolation(ctx context.Context, config ActionConfig) (ActionResult, error) {
	if !isPrivileged() {
		return ActionResult{}, errors.New("network isolation requires a privileged rescue helper")
	}
	addresses, port, err := resolveControlPlane(ctx, config.ControlPlaneURL)
	if err != nil {
		return ActionResult{}, err
	}
	script := controlPlaneIsolationRules(addresses, port)
	return ActionResult{
		Stdout: []byte("network_isolation=control-plane-only-scheduled\n"),
		AfterReport: func(ctx context.Context) error {
			time.Sleep(2 * time.Second)
			state := isolationState{Mode: rescuev1.NetworkIsolationMode_NETWORK_ISOLATION_MODE_CONTROL_PLANE_ONLY, AppliedAt: time.Now().UTC()}
			if err := saveIsolationState(config, state); err != nil {
				return fmt.Errorf("save network isolation state: %w", err)
			}
			if err := applyNftScript(ctx, config, script); err != nil {
				_ = os.Remove(isolationPath(config))
				return err
			}
			return nil
		},
	}, nil
}

func restoreNetwork(ctx context.Context, config ActionConfig) (ActionResult, error) {
	if !isPrivileged() {
		return ActionResult{}, errors.New("restoring network access requires a privileged rescue helper")
	}
	if err := deleteNftIsolation(ctx); err != nil {
		return ActionResult{}, err
	}
	if path := isolationPath(config); path != "" {
		_ = os.Remove(path)
	}
	return ActionResult{Stdout: []byte("network_isolation=removed\n")}, nil
}

func networkIsolationStatus(config ActionConfig) (rescuev1.NetworkIsolationMode, []string) {
	data, err := os.ReadFile(isolationPath(config))
	if err != nil {
		return rescuev1.NetworkIsolationMode_NETWORK_ISOLATION_MODE_NONE, nil
	}
	var state isolationState
	if json.Unmarshal(data, &state) != nil {
		return rescuev1.NetworkIsolationMode_NETWORK_ISOLATION_MODE_UNSPECIFIED, nil
	}
	return state.Mode, append([]string(nil), state.Interfaces...)
}

func interfacesForMode(mode rescuev1.NetworkIsolationMode) ([]string, error) {
	var names []string
	switch mode {
	case rescuev1.NetworkIsolationMode_NETWORK_ISOLATION_MODE_PUBLIC_INTERFACES:
		for _, family := range [][]string{{"-j", "route", "show", "default"}, {"-j", "-6", "route", "show", "default"}} {
			output, _, err := platformCommand(context.Background(), "ip", family...)
			if err != nil {
				continue
			}
			var routes []struct {
				Dev string `json:"dev"`
			}
			if err := json.Unmarshal(output, &routes); err != nil {
				return nil, fmt.Errorf("decode default routes: %w", err)
			}
			for _, route := range routes {
				if route.Dev != "" && route.Dev != "lo" {
					names = append(names, route.Dev)
				}
			}
		}
	case rescuev1.NetworkIsolationMode_NETWORK_ISOLATION_MODE_TAILSCALE_INTERFACES:
		interfaces, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		for _, item := range interfaces {
			if strings.HasPrefix(strings.ToLower(item.Name), "tailscale") {
				names = append(names, item.Name)
			}
		}
	default:
		return nil, errors.New("unsupported interface isolation mode")
	}
	names = uniqueStrings(names)
	if len(names) == 0 {
		return nil, errors.New("no matching network interfaces were found")
	}
	return names, nil
}

func interfaceIsolationRules(interfaces []string) string {
	quoted := make([]string, len(interfaces))
	for index, name := range interfaces {
		quoted[index] = strconv.Quote(name)
	}
	set := strings.Join(quoted, ", ")
	return fmt.Sprintf("table inet %s {\n chain input { type filter hook input priority -50; policy accept; iifname { %s } drop; }\n chain output { type filter hook output priority -50; policy accept; oifname { %s } drop; }\n}\n", linuxIsolationTable, set, set)
}

func controlPlaneIsolationRules(addresses []net.IP, port uint16) string {
	var ipv4, ipv6 []string
	for _, address := range addresses {
		if address.To4() != nil {
			ipv4 = append(ipv4, address.String())
		} else {
			ipv6 = append(ipv6, address.String())
		}
	}
	var inputAllow, outputAllow strings.Builder
	if len(ipv4) > 0 {
		inputAllow.WriteString(fmt.Sprintf(" ip saddr { %s } tcp sport %d ct state established accept;", strings.Join(ipv4, ", "), port))
		inputAllow.WriteString(fmt.Sprintf(" ip saddr { %s } udp sport %d ct state established accept;", strings.Join(ipv4, ", "), port))
		outputAllow.WriteString(fmt.Sprintf(" ip daddr { %s } tcp dport %d accept;", strings.Join(ipv4, ", "), port))
		outputAllow.WriteString(fmt.Sprintf(" ip daddr { %s } udp dport %d accept;", strings.Join(ipv4, ", "), port))
	}
	if len(ipv6) > 0 {
		inputAllow.WriteString(fmt.Sprintf(" ip6 saddr { %s } tcp sport %d ct state established accept;", strings.Join(ipv6, ", "), port))
		inputAllow.WriteString(fmt.Sprintf(" ip6 saddr { %s } udp sport %d ct state established accept;", strings.Join(ipv6, ", "), port))
		outputAllow.WriteString(fmt.Sprintf(" ip6 daddr { %s } tcp dport %d accept;", strings.Join(ipv6, ", "), port))
		outputAllow.WriteString(fmt.Sprintf(" ip6 daddr { %s } udp dport %d accept;", strings.Join(ipv6, ", "), port))
	}
	return fmt.Sprintf("table inet %s {\n chain input { type filter hook input priority -50; policy accept; iifname lo accept;%s drop; }\n chain output { type filter hook output priority -50; policy accept; oifname lo accept;%s drop; }\n}\n", linuxIsolationTable, inputAllow.String(), outputAllow.String())
}

func applyNftScript(ctx context.Context, config ActionConfig, script string) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return errors.New("nftables is required for emergency network isolation")
	}
	directory := filepath.Dir(isolationPath(config))
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".komari-nft-*.conf")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer os.Remove(path)
	if _, err := temporary.WriteString(script); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	checkTable := fmt.Sprintf("%s_check_%d", linuxIsolationTable, os.Getpid())
	checkScript := strings.Replace(script, "table inet "+linuxIsolationTable, "table inet "+checkTable, 1)
	if err := os.WriteFile(path, []byte(checkScript), 0o600); err != nil {
		return err
	}
	if _, stderr, err := platformCommand(ctx, "nft", "-c", "-f", path); err != nil {
		return fmt.Errorf("validate Komari network isolation: %s: %w", strings.TrimSpace(string(stderr)), err)
	}
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		return err
	}
	_ = deleteNftIsolation(context.Background())
	_, stderr, err := platformCommand(ctx, "nft", "-f", path)
	if err != nil {
		return fmt.Errorf("apply Komari network isolation: %s: %w", strings.TrimSpace(string(stderr)), err)
	}
	return nil
}

func deleteNftIsolation(ctx context.Context) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return errors.New("nftables is required for emergency network isolation")
	}
	// Listing first avoids depending on localized nft error output when the
	// dedicated table does not exist.
	if _, _, err := platformCommand(ctx, "nft", "list", "table", "inet", linuxIsolationTable); err != nil {
		return nil
	}
	_, stderr, err := platformCommand(ctx, "nft", "delete", "table", "inet", linuxIsolationTable)
	if err != nil {
		return fmt.Errorf("remove Komari network isolation: %s: %w", strings.TrimSpace(string(stderr)), err)
	}
	return nil
}

func resolveControlPlane(ctx context.Context, endpoint string) ([]net.IP, uint16, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, 0, errors.New("a valid HTTP(S) control plane URL is required")
	}
	port := uint16(443)
	if parsed.Scheme == "http" {
		port = 80
	}
	if parsed.Port() != "" {
		value, err := strconv.ParseUint(parsed.Port(), 10, 16)
		if err != nil || value == 0 {
			return nil, 0, errors.New("control plane port is invalid")
		}
		port = uint16(value)
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIP(lookupCtx, "ip", parsed.Hostname())
	if err != nil || len(addresses) == 0 {
		return nil, 0, fmt.Errorf("resolve control plane: %w", err)
	}
	return addresses, port, nil
}

func isolationPath(config ActionConfig) string {
	if value := strings.TrimSpace(config.IsolationStatePath); value != "" {
		return value
	}
	return "/etc/komari-agent/rescue-isolation.json"
}

func saveIsolationState(config ActionConfig, state isolationState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	path := isolationPath(config)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
