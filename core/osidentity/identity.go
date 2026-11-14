// Package osidentity configures child processes without ever changing the
// multithreaded Agent's process-wide identity or inheriting its credentials.
package osidentity

import (
	"errors"
	"os"
	"os/user"
	"strings"
)

type Identity struct{ User *user.User }

func Resolve(name string) (*Identity, error) {
	return resolveWorkspace(name, false)
}

// ResolveRemote requires both the remote root grant and any explicit local list.
func ResolveRemote(name string, rootAllowed bool) (*Identity, error) {
	identity, err := resolveWorkspace(name, rootAllowed)
	if err != nil {
		return nil, err
	}
	if identity.User.Uid == "0" && !rootAllowed {
		return nil, errors.New("root WebSSH requires approved root execution permission")
	}
	return identity, nil
}

// ResolveExecution selects a fixed account independently of the daemon account.
func ResolveExecution(asRoot bool) (*Identity, error) {
	name := "komari"
	if asRoot {
		name = "root"
	}
	identity, err := lookup(name)
	if err != nil {
		return nil, err
	}
	if !asRoot && identity.User.Uid == "0" {
		return nil, errors.New("the komari execution account must not be UID 0")
	}
	return identity, nil
}

func lookup(name string) (*Identity, error) {
	if name == "" || name != strings.TrimSpace(name) || len(name) > 128 || strings.ContainsAny(name, "\x00\r\n") {
		return nil, errors.New("an explicit OS username is required")
	}
	target, err := user.Lookup(name)
	if err != nil {
		return nil, errors.New("selected OS account does not exist")
	}
	current, err := user.Current()
	if err != nil {
		return nil, err
	}
	if current.Uid != "0" && current.Uid != target.Uid {
		return nil, errors.New("Agent cannot switch to another OS account")
	}
	return &Identity{User: target}, nil
}

func resolveWorkspace(name string, rootAllowed bool) (*Identity, error) {
	identity, err := lookup(name)
	if err != nil {
		return nil, err
	}
	target := identity.User
	allowed := os.Getenv("KOMARI_WORKSPACE_USERS")
	if allowed != "" {
		found := false
		for _, entry := range strings.Split(allowed, ",") {
			if strings.TrimSpace(entry) == target.Username {
				found = true
			}
		}
		if !found {
			return nil, errors.New("OS account is not in KOMARI_WORKSPACE_USERS")
		}
	} else if target.Uid == "0" && !rootAllowed {
		return nil, errors.New("root requires explicit KOMARI_WORKSPACE_USERS authorization on the Agent")
	}
	return identity, nil
}

func (i *Identity) Environment() []string {
	return []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + i.User.HomeDir, "USER=" + i.User.Username,
		"LOGNAME=" + i.User.Username, "TERM=xterm-256color", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
}
