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

func Run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: komari-host diagnose|migrate|update; apply is unavailable until host transaction support is installed")
	}
	switch args[0] {
	case "version":
		_, err := fmt.Fprintln(out, "komari-host protocol=2 host-actions=none")
		return err
	case "apply":
		return errors.New("host identity conversion and rescue installation are not implemented in this version; no state was changed")
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
