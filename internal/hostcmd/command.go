// Package hostcmd implements a short-lived administrator tool. It installs
// trusted metadata and diagnoses services; it is not a daemon or a sudo bypass.
package hostcmd

import (
	"errors"
	"flag"
	"fmt"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"io"
)

// ReleaseVersion is set by release builds. Never resolve "latest" during a
// privileged install, or infer executable authority from daemon-writable data.
var ReleaseVersion string

func Run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: komari-host diagnose|migrate|update|trust|apply|resume|restore")
	}
	switch args[0] {
	case "version":
		_, err := fmt.Fprintf(out, "komari-host release=%s protocol=2; host actions require Linux systemd, protected trust and fresh PAM authentication\n", ReleaseVersion)
		return err
	case "apply":
		return apply(args[1:], out)
	case "trust":
		return trust(args[1:], out)
	case "fetch-helper":
		return fetchHelper(args[1:], out)
	case "resume", "restore":
		return resume(args[1:], out, args[0] == "restore")
	case "diagnose":
		fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
		fs.SetOutput(out)
		path := fs.String("manifest", "", "installed service manifest")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *path == "" {
			return errors.New("--manifest is required; do not infer installation from HOME")
		}
		m, err := hostops.ReadManifest(*path)
		if err != nil {
			return err
		}
		p, err := hostops.ReadPolicy(m)
		if err != nil {
			return err
		}
		return diagnose(m, p, out)
	case "install":
		return install(args[1:], out)
	case "migrate":
		return migrate(args[1:], out)
	case "update":
		return update(args[1:], out)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
