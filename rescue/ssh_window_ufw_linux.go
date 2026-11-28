package rescue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

type sshUFWFamily struct {
	iptables, chain, beforeChain, userChain, family, set string
}

var sshUFWFamilies = [...]sshUFWFamily{
	{"iptables", "ufw-after-input", "ufw-before-input", "ufw-user-input", "inet", sshWindowV4Set},
	{"ip6tables", "ufw6-after-input", "ufw6-before-input", "ufw6-user-input", "inet6", sshWindowV6Set},
}

type sshUFWState struct {
	enabled, linked, setExists bool
	element                    *sshWindowElement
}

func (f sshUFWFamily) rule(config sshWindowConfig) []string {
	return []string{"-i", config.Interface, "-p", "tcp", "-m", "tcp", "--dport", strconv.FormatUint(uint64(config.Port), 10),
		"-m", "set", "--match-set", f.set, "src", "-j", "ACCEPT"}
}

func runSSHWindowUFW(ctx context.Context, name string, args ...string) error {
	if output, err := sshWindowCommand(ctx, name, args...); err != nil {
		return fmt.Errorf("%s %s: %s: %w", name, strings.Join(args, " "), truncateError(string(output)), err)
	}
	return nil
}

func (f sshUFWFamily) inspect(ctx context.Context, config sshWindowConfig, requireHook bool) (sshUFWState, error) {
	var state sshUFWState
	rules, err := sshWindowCommand(ctx, f.iptables+"-save")
	if err != nil {
		return state, fmt.Errorf("read UFW %s rules: %s: %w", f.family, truncateError(string(rules)), err)
	}
	table := ""
	var before, after, user, references int
	var outOfOrder bool
	expected := append([]string{"-A", f.chain}, f.rule(config)...)
	for line := range strings.Lines(string(rules)) {
		fields := strings.Fields(line)
		if len(fields) == 1 && strings.HasPrefix(fields[0], "*") {
			table = fields[0]
		}
		if table == "*filter" {
			switch {
			case slices.Equal(fields, []string{"-A", "INPUT", "-j", f.beforeChain}):
				before++
			case slices.Equal(fields, []string{"-A", "INPUT", "-j", f.chain}):
				after++
				outOfOrder = before != 1
			case slices.Equal(fields, []string{"-A", f.beforeChain, "-j", f.userChain}):
				user++
			}
		}
		if len(fields) < 3 || fields[0] != "-A" {
			continue
		}
		for i := 2; i < len(fields)-1; i++ {
			if !slices.Contains([]string{"--match-set", "--add-set", "--del-set", "--map-set"}, fields[i]) || fields[i+1] != f.set {
				continue
			}
			references++
			if requireHook && (table != "*filter" || !slices.Equal(fields, expected) || references != 1) {
				return state, fmt.Errorf("%w: unexpected UFW rule referencing %s", errSSHWindowRules, f.set)
			}
		}
	}
	if requireHook && (outOfOrder || before != user || before != after || before > 1) {
		return state, fmt.Errorf("%w: incomplete %s UFW input chain", errSSHWindowRules, f.family)
	}
	state.enabled = !outOfOrder && before == 1 && after == 1 && user == 1
	state.linked = references == 1 && state.enabled

	header, err := sshWindowCommand(ctx, "ipset", "list", "-t", f.set)
	if err != nil {
		if strings.Contains(string(header), "The set with the given name does not exist") && references == 0 {
			return state, nil
		}
		return state, fmt.Errorf("read UFW set %s: %s: %w", f.set, truncateError(string(header)), err)
	}
	if requireHook {
		// Also catch references from other firewall tables, families and list:set.
		var refCount = -1
		for line := range strings.Lines(string(header)) {
			if value, ok := strings.CutPrefix(strings.TrimSpace(line), "References: "); ok {
				refCount, err = strconv.Atoi(value)
				if err != nil {
					return state, fmt.Errorf("%w: invalid references for %s", errSSHWindowRules, f.set)
				}
			}
		}
		if refCount != references || references > 0 && !state.enabled {
			return state, fmt.Errorf("%w: unexpected references or an unlinked UFW chain for %s", errSSHWindowRules, f.set)
		}
	}
	data, err := sshWindowCommand(ctx, "ipset", "save", f.set)
	if err != nil {
		return state, fmt.Errorf("read UFW entries for %s: %s: %w", f.set, truncateError(string(data)), err)
	}
	state.element, err = parseSSHWindowIPSet(string(data), f)
	state.setExists = err == nil
	return state, err
}

func parseSSHWindowIPSet(data string, f sshUFWFamily) (*sshWindowElement, error) {
	bad := fmt.Errorf("%w: invalid kernel timeout set %s", errSSHWindowRules, f.set)
	lines := strings.Split(strings.TrimSpace(data), "\n")
	fields := strings.Fields(lines[0])
	if len(fields) < 8 || !slices.Equal(fields[:5], []string{"create", f.set, "hash:ip", "family", f.family}) {
		return nil, bad
	}
	found := func(option, value string) bool {
		i := slices.Index(fields[5:], option)
		return i >= 0 && i+6 < len(fields) && fields[i+6] == value
	}
	if !found("maxelem", "1") || !found("timeout", strconv.Itoa(int(temporarySSHDuration/time.Second))) ||
		!slices.Contains(fields[5:], "comment") || slices.Contains(fields[5:], "netmask") || slices.Contains(fields[5:], "bitmask") {
		return nil, bad
	}
	var element *sshWindowElement
	for _, line := range lines[1:] {
		entry := strings.Fields(line)
		if len(entry) != 7 || entry[0] != "add" || entry[1] != f.set || entry[3] != "timeout" || entry[5] != "comment" {
			return nil, bad
		}
		ip, ipErr := netip.ParseAddr(entry[2])
		seconds, timeoutErr := strconv.Atoi(entry[4])
		id, commentErr := strconv.Unquote(entry[6])
		if ipErr != nil || timeoutErr != nil || commentErr != nil || element != nil || !ip.IsGlobalUnicast() ||
			ip.Zone() != "" || ip.Is4In6() || ip.Is4() != (f.family == "inet") ||
			seconds <= 0 || seconds > int(temporarySSHDuration/time.Second) || !validSSHGrantID(id) {
			return nil, bad
		}
		element = &sshWindowElement{Address: ip, Comment: id, Expires: json.Number(strconv.Itoa(seconds))}
	}
	return element, nil
}

func (config sshWindowConfig) inspectUFW(ctx context.Context, requireHook bool) (*sshWindowElement, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var active *sshWindowElement
	for i, f := range sshUFWFamilies {
		state, err := f.inspect(ctx, config, requireHook)
		if err != nil {
			return nil, err
		}
		if requireHook && i == 0 && !state.enabled {
			return nil, fmt.Errorf("%w: UFW's IPv4 input chains are not loaded; check sudo ufw status", errSSHWindowRules)
		}
		if state.element != nil && (!requireHook || state.linked) {
			if active != nil {
				return nil, fmt.Errorf("%w: more than one temporary SSH entry is present", errSSHWindowRules)
			}
			active = state.element
		}
	}
	return active, nil
}

func (f sshUFWFamily) prepare(ctx context.Context, config sshWindowConfig, state sshUFWState) error {
	if !state.enabled {
		return fmt.Errorf("%s is not enabled in UFW", f.family)
	}
	if !state.setExists {
		if err := runSSHWindowUFW(ctx, "ipset", "create", f.set, "hash:ip", "family", f.family, "maxelem", "1",
			"timeout", strconv.Itoa(int(temporarySSHDuration/time.Second)), "comment"); err != nil {
			return err
		}
	}
	if state.linked {
		return nil
	}
	// A UFW reload drops the rule, but can leave the old set in the kernel.
	// Never relink an old permit. Append after UFW's user and after rules.
	if err := runSSHWindowUFW(ctx, "ipset", "flush", f.set); err != nil {
		return err
	}
	args := append([]string{"-w", "2", "-A", f.chain}, f.rule(config)...)
	if err := runSSHWindowUFW(ctx, f.iptables, args...); err != nil {
		return err
	}
	observed, err := f.inspect(ctx, config, true)
	if err != nil {
		return err
	}
	if !observed.linked {
		return errors.New("UFW reloaded while preparing temporary SSH; retry")
	}
	return nil
}

func (config sshWindowConfig) prepareUFW(ctx context.Context) error {
	sshAccessMu.Lock()
	defer sshAccessMu.Unlock()
	for _, f := range sshUFWFamilies {
		state, err := f.inspect(ctx, config, true)
		if err != nil {
			return err
		}
		if state.enabled {
			if state.linked && state.element != nil {
				return errors.New("an active UFW temporary SSH entry already exists; wait for it to expire before setting up again")
			}
			if err := f.prepare(ctx, config, state); err != nil {
				return err
			}
		} else if f.family == "inet" {
			return errors.New("UFW IPv4 input hook disappeared during setup")
		}
	}
	return nil
}

func (config sshWindowConfig) clearUFWGrant(ctx context.Context) error {
	var result error
	for _, f := range sshUFWFamilies {
		// Check the set directly: revocation must work even when UFW has
		// removed the associated rule.
		data, err := sshWindowCommand(ctx, "ipset", "save", f.set)
		if err != nil && strings.Contains(string(data), "The set with the given name does not exist") {
			continue
		}
		if err == nil {
			_, err = parseSSHWindowIPSet(string(data), f)
		}
		if err == nil {
			err = runSSHWindowUFW(ctx, "ipset", "flush", f.set)
		}
		if err != nil {
			result = errors.Join(result, fmt.Errorf("clear UFW temporary SSH set %s: %w", f.set, err))
		}
	}
	return result
}

func (config sshWindowConfig) replaceUFWGrant(ctx context.Context, grant *sshWindowGrant) error {
	f := sshUFWFamilies[1]
	if grant.Source.Is4() {
		f = sshUFWFamilies[0]
	}
	state, err := f.inspect(ctx, config, true)
	if err != nil {
		return err
	}
	if err := f.prepare(ctx, config, state); err != nil {
		return err
	}
	// Cross-family replacement is intentionally fail-closed: close the old
	// grant completely before opening the new one.
	if err := config.clearUFWGrant(ctx); err != nil {
		return err
	}
	seconds := int(time.Until(grant.ExpiresAt) / time.Second)
	if seconds < 1 || seconds > int(temporarySSHDuration/time.Second) {
		return errors.New("temporary SSH authorization has no remaining kernel timeout")
	}
	return runSSHWindowUFW(ctx, "ipset", "add", f.set, grant.Source.String(), "timeout", strconv.Itoa(seconds), "comment", grant.ID)
}
