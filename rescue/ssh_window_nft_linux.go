//go:build linux

package rescue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os/exec"
	"reflect"
	"strings"
	"time"
)

type sshWindowElement struct {
	Address netip.Addr  `json:"val"`
	Comment string      `json:"comment"`
	Timeout json.Number `json:"timeout"`
	Expires json.Number `json:"expires"`
}

type sshWindowNftTable struct {
	Entries []struct {
		Chain *struct {
			Name string `json:"name"`
			Type string `json:"type"`
			Hook string `json:"hook"`
		} `json:"chain"`
		Set *struct {
			Name     string          `json:"name"`
			Type     json.RawMessage `json:"type"`
			Flags    []string        `json:"flags"`
			Elements json.RawMessage `json:"elem"`
		} `json:"set"`
		Rule *struct {
			Chain       string `json:"chain"`
			Expressions []any  `json:"expr"`
		} `json:"rule"`
	} `json:"nftables"`
}

// inspect checks the narrow rules linked to both sets. Their placement
// relative to other rules is managed by the host's firewall configuration.
func (config sshWindowConfig) inspect(ctx context.Context, requireHook bool) (*sshWindowElement, error) {
	output, stderr, err := platformCommand(ctx, "nft", "-j", "list", "table", "inet", config.Table)
	if err != nil {
		if !requireHook && strings.Contains(string(stderr), "No such file or directory") {
			return nil, nil
		}
		return nil, fmt.Errorf("read nftables SSH table %s: %s: %w", config.Table, strings.TrimSpace(string(stderr)), err)
	}
	var table sshWindowNftTable
	if err := json.Unmarshal(output, &table); err != nil {
		return nil, fmt.Errorf("decode nftables SSH table: %w", err)
	}
	sets := make(map[string]bool, 2)
	rules := make(map[string]int, 2)
	input := false
	var element *sshWindowElement
	for _, entry := range table.Entries {
		if c := entry.Chain; c != nil && c.Name == config.Chain && c.Hook == "input" && c.Type == "filter" {
			input = true
		}
		if r := entry.Rule; r != nil && requireHook {
			expressions, err := json.Marshal(r.Expressions)
			if err != nil {
				return nil, err
			}
			for _, set := range []string{sshWindowV4Set, sshWindowV6Set} {
				if r.Chain == config.Chain && reflect.DeepEqual(r.Expressions, config.ruleExpressions(set)) {
					rules[set]++
				} else if strings.Contains(string(expressions), `"@`+set+`"`) {
					return nil, fmt.Errorf("temporary SSH set %s is referenced by an unexpected rule in %s", set, r.Chain)
				}
			}
		}
		if s := entry.Set; s != nil && (s.Name == sshWindowV4Set || s.Name == sshWindowV6Set) {
			wantType := "ipv6_addr"
			if s.Name == sshWindowV4Set {
				wantType = "ipv4_addr"
			}
			if string(s.Type) != fmt.Sprintf("%q", wantType) || !reflect.DeepEqual(s.Flags, []string{"timeout"}) {
				return nil, fmt.Errorf("temporary SSH set %s must be a dedicated %s timeout set", s.Name, wantType)
			}
			sets[s.Name] = true
			var items []struct {
				Element sshWindowElement `json:"elem"`
			}
			if len(s.Elements) > 0 {
				if err := json.Unmarshal(s.Elements, &items); err != nil {
					return nil, fmt.Errorf("invalid entries in temporary SSH set %s: %w", s.Name, err)
				}
			}
			for _, item := range items {
				expiry, err := item.Element.Expires.Float64()
				timeout, timeoutErr := item.Element.Timeout.Float64()
				if err != nil || timeoutErr != nil || timeout <= 0 || timeout > temporarySSHDuration.Seconds() ||
					!validSSHGrantID(item.Element.Comment) || !item.Element.Address.IsValid() ||
					item.Element.Address.Is4() != (s.Name == sshWindowV4Set) {
					return nil, fmt.Errorf("unexpected entry in temporary SSH set %s", s.Name)
				}
				if expiry <= 0 {
					continue
				}
				if element != nil {
					return nil, errors.New("more than one temporary SSH entry is present")
				}
				value := item.Element
				element = &value
			}
		}
	}
	if requireHook && (!input || !sets[sshWindowV4Set] || !sets[sshWindowV6Set] ||
		rules[sshWindowV4Set] != 1 || rules[sshWindowV6Set] != 1) {
		return nil, fmt.Errorf("temporary SSH rules are missing or do not match %s/%s, %s TCP %d", config.Table, config.Chain, config.Interface, config.Port)
	}
	return element, nil
}

func (config sshWindowConfig) ruleExpressions(set string) []any {
	protocol := "ip6"
	if set == sshWindowV4Set {
		protocol = "ip"
	}
	match := func(left any, right any) any {
		return map[string]any{"match": map[string]any{"op": "==", "left": left, "right": right}}
	}
	payload := func(protocol, field string) any {
		return map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}
	}
	return []any{
		match(map[string]any{"meta": map[string]any{"key": "iifname"}}, config.Interface),
		match(payload(protocol, "saddr"), "@"+set),
		match(payload("tcp", "dport"), float64(config.Port)),
		map[string]any{"accept": nil},
	}
}

func (config sshWindowConfig) flushCommands() string {
	return fmt.Sprintf("flush set inet %s %s\nflush set inet %s %s\n",
		config.Table, sshWindowV4Set, config.Table, sshWindowV6Set)
}

func (config sshWindowConfig) apply(ctx context.Context, batch string) error {
	command := exec.CommandContext(ctx, "nft", "-f", "-")
	command.Stdin = strings.NewReader(batch)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apply temporary SSH nftables transaction: %s: %w", truncateError(string(output)), err)
	}
	return nil
}

// A journal write precedes the kernel transaction. Reconciling the unique
// element comment settles a crash or a lost command response without replaying
// the transaction or changing the kernel's original expiration.
func (config sshWindowConfig) reconcile(element *sshWindowElement) (sshWindowState, *sshWindowGrant, error) {
	state, err := config.loadState()
	if err != nil {
		return state, nil, err
	}
	matches := func(grant *sshWindowGrant) bool {
		return grant != nil && element != nil && grant.ID == element.Comment && grant.Source == element.Address
	}
	if element != nil && !matches(state.Pending) && !matches(state.Current) {
		return state, nil, errors.New("temporary SSH entry does not belong to a recorded grant")
	}
	if state.Pending != nil {
		if matches(state.Pending) {
			state.Current = state.Pending
			logSSHWindow("granted", config, state.Current)
		} else if element == nil {
			// With no readable live entry, retain the last attempted ID as a
			// tombstone. An old request cannot reopen access after a reload.
			state.Current = state.Pending
		}
		state.Pending = nil
		if err := config.saveState(state); err != nil {
			return state, nil, err
		}
	}
	if !matches(state.Current) {
		return state, nil, nil
	}
	remaining, err := element.Expires.Float64()
	if err != nil || remaining <= 0 {
		return state, nil, err
	}
	active := *state.Current
	observedExpiry := time.Now().Add(time.Duration(remaining * float64(time.Second)))
	if observedExpiry.Before(active.ExpiresAt) {
		active.ExpiresAt = observedExpiry
	}
	return state, &active, nil
}

func logSSHWindow(action string, config sshWindowConfig, grant *sshWindowGrant) {
	log.Printf("temporary SSH %s grant=%s backend=nftables table=%s chain=%s interface=%s port=%d source=%s expires=%s",
		action, grant.ID, config.Table, config.Chain, config.Interface, config.Port, grant.Source, grant.ExpiresAt.Format(time.RFC3339))
}
