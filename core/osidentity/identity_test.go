package osidentity

import (
	"os/user"
	"strings"
	"testing"
)

func TestExplicitAccountAndAllowlist(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KOMARI_WORKSPACE_USERS", current.Username)
	for _, name := range []string{"", " ", "\n", current.Username + "\x00"} {
		if _, err := Resolve(name); err == nil {
			t.Fatalf("accepted invalid account %q", name)
		}
	}
	identity, err := Resolve(current.Username)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_TOKEN", "must-not-be-inherited")
	t.Setenv("KOMARI_SECRET", "must-not-be-inherited")
	environment := strings.Join(identity.Environment(), "\n")
	if strings.Contains(environment, "must-not-be-inherited") || strings.Contains(environment, "AGENT_TOKEN") {
		t.Fatal("Agent secrets inherited")
	}
	t.Setenv("KOMARI_WORKSPACE_USERS", "account-that-does-not-exist")
	if _, err := Resolve(current.Username); err == nil {
		t.Fatal("allowlist ignored")
	}
}

func TestRootRequiresLocalOptIn(t *testing.T) {
	root, err := user.LookupId("0")
	if err != nil {
		t.Skip("no Unix root account")
	}
	t.Setenv("KOMARI_WORKSPACE_USERS", "")
	if _, err := Resolve(root.Username); err == nil {
		t.Fatal("implicit root was allowed")
	}
}
