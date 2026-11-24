package rescue

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/google/uuid"
)

type sshNftChain struct {
	Table string `json:"table"`
	Name  string `json:"name"`
	Set   string `json:"set"`
}

type sshNftRuleset struct {
	Entries []struct {
		Chain *struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
			Hook   string `json:"hook"`
			Type   string `json:"type"`
		} `json:"chain"`
		Rule *struct {
			Family  string `json:"family"`
			Table   string `json:"table"`
			Chain   string `json:"chain"`
			Comment string `json:"comment"`
			Handle  uint64 `json:"handle"`
		} `json:"rule"`
		Set *struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
		} `json:"set"`
	} `json:"nftables"`
}

var sshNftIdentifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z_0-9]*$`)

func readSSHNftRuleset(ctx context.Context) (sshNftRuleset, error) {
	var ruleset sshNftRuleset
	stdout, stderr, err := platformCommand(ctx, "nft", "-j", "-a", "list", "ruleset")
	if err != nil {
		return ruleset, fmt.Errorf("inspect nftables input chains: %s: %w", stderr, err)
	}
	if err := json.Unmarshal(stdout, &ruleset); err != nil {
		return ruleset, fmt.Errorf("decode nftables ruleset: %w", err)
	}
	return ruleset, nil
}

func resolveSSHInputChain(ctx context.Context) (*sshNftChain, error) {
	ruleset, err := readSSHNftRuleset(ctx)
	if err != nil {
		return nil, err
	}
	return ruleset.sshInputChain()
}

func (ruleset sshNftRuleset) sshInputChain() (*sshNftChain, error) {
	var target *sshNftChain
	for _, entry := range ruleset.Entries {
		chain := entry.Chain
		if chain == nil || chain.Table == temporarySSHTable {
			continue
		}
		if chain.Type == "filter" && (chain.Hook == "ingress" || chain.Hook == "prerouting") {
			return nil, fmt.Errorf("nftables has an earlier %s filter in %s/%s; verify SSH access in the host firewall", chain.Hook, chain.Table, chain.Name)
		}
		if chain.Hook != "input" || chain.Family == "arp" {
			continue
		}
		if target != nil || chain.Family != "inet" || chain.Type != "filter" ||
			!sshNftIdentifier.MatchString(chain.Table) || !sshNftIdentifier.MatchString(chain.Name) {
			return nil, fmt.Errorf("temporary SSH requires a single inet nftables input filter; verify SSH access in the host firewall")
		}
		target = &sshNftChain{Table: chain.Table, Name: chain.Name, Set: "komari_ssh_" + uuid.New().String()[0:8]}
	}
	return target, nil
}

func removeSSHInputRule(ctx context.Context, chain sshNftChain) error {
	ruleset, err := readSSHNftRuleset(ctx)
	if err != nil {
		return err
	}
	for _, entry := range ruleset.Entries {
		rule := entry.Rule
		if rule == nil || rule.Family != "inet" || rule.Table != chain.Table || rule.Chain != chain.Name ||
			rule.Comment != chain.Set || rule.Handle == 0 {
			continue
		}
		if _, stderr, err := platformCommand(ctx, "nft", "delete", "rule", "inet", chain.Table, chain.Name, "handle", fmt.Sprint(rule.Handle)); err != nil {
			return fmt.Errorf("delete temporary SSH nftables rule: %s: %w", stderr, err)
		}
	}
	for _, entry := range ruleset.Entries {
		set := entry.Set
		if set != nil && set.Family == "inet" && set.Table == chain.Table && set.Name == chain.Set {
			if _, stderr, err := platformCommand(ctx, "nft", "delete", "set", "inet", chain.Table, chain.Set); err != nil {
				return fmt.Errorf("delete temporary SSH nftables set: %s: %w", stderr, err)
			}
		}
	}
	return nil
}
