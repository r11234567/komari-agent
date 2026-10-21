//go:build linux

package hostcmd

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"time"

	"github.com/komari-monitor/komari-agent/core/hostops"
)

// No rootok, sudo cache, su, nullok, remote conversation, or password pipe.
// pam_unix authenticates the selected account even when the caller is root.
const pamProfile = "# Komari host: fresh local password and account validity\nauth required pam_unix.so\naccount required pam_unix.so\n"
const pamPath = "/etc/pam.d/komari-host"

func installPAM() error {
	if err := hostops.TrustedPath("/etc/pam.d"); err != nil {
		return err
	}
	if b, err := os.ReadFile(pamPath); err == nil {
		if string(b) != pamProfile {
			return errors.New("existing komari-host PAM profile differs; review it locally before replacing")
		}
		return hostops.TrustedPath(pamPath)
	} else if !os.IsNotExist(err) {
		return err
	}
	return hostops.AtomicWrite(pamPath, []byte(pamProfile), 0o644)
}
func authenticationReady() error {
	if err := hostops.TrustedPath("/usr/bin/pamtester"); err != nil {
		return errors.New("install the distribution pamtester package before host apply")
	}
	if err := hostops.TrustedPath(pamPath); err != nil {
		return err
	}
	b, err := os.ReadFile(pamPath)
	if err != nil {
		return err
	}
	if string(b) != pamProfile {
		return errors.New("komari-host PAM profile must require pam_unix authenticate and account checks")
	}
	return nil
}
func authenticate() (string, error) {
	if err := authenticationReady(); err != nil {
		return "", err
	}
	account := "root"
	if os.Getenv("SUDO_USER") != "" {
		account = os.Getenv("SUDO_USER")
		u, err := user.Lookup(account)
		if err != nil || u.Uid != os.Getenv("SUDO_UID") {
			return "", errors.New("sudo caller identity is inconsistent")
		}
	}
	if !hostops.ValidService(account) {
		return "", errors.New("invalid local authentication account")
	}
	u, err := user.Lookup(account)
	if err != nil {
		return "", err
	}
	if _, err = strconv.Atoi(u.Uid); err != nil {
		return "", err
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("fresh local PAM authentication requires a controlling terminal")
	}
	defer tty.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/pamtester", "komari-host", account, "authenticate", "acct_mgmt")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.Stdin = tty
	cmd.Stdout = tty
	cmd.Stderr = tty
	if err = cmd.Run(); err != nil {
		return "", errors.New("fresh PAM authentication or account validation failed")
	}
	return account, nil
}
