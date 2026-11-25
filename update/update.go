package update

import "errors"

var (
	CurrentVersion string = "0.0.1"
	Repo           string = "r11234567/komari-agent"
)

// CheckAndUpdate preserves the CLI diagnostic for configurations that still
// request daemon self-updates. Installed binaries are updated by the host tool.
func CheckAndUpdate() error {
	return errors.New("daemon self-update is disabled; stage an administrator-verified release and run komari-host update --manifest <path> --artifact <binary> --sha256 <trusted-digest>")
}
