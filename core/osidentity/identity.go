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
	} else if target.Uid == "0" {
		return nil, errors.New("root requires explicit KOMARI_WORKSPACE_USERS authorization on the Agent")
	}
	if current.Uid != "0" && current.Uid != target.Uid {
		return nil, errors.New("Agent cannot switch to another OS account")
	}
	return &Identity{User: target}, nil
}

func (i *Identity) Environment() []string {
	return []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + i.User.HomeDir, "USER=" + i.User.Username,
		"LOGNAME=" + i.User.Username, "TERM=xterm-256color", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
}
