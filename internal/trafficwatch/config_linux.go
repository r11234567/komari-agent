package trafficwatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type Config struct {
	Interface      string          `json:"interface"`
	LocalAddresses []netip.Addr    `json:"local_addresses"`
	ScratchDir     string          `json:"scratch_dir"`
	StateDir       string          `json:"state_dir"`
	UploadDir      string          `json:"upload_dir,omitempty"`
	Xray           *XrayConfig     `json:"xray"`
	Services       []ServiceConfig `json:"services"`
	Thresholds     thresholds      `json:"thresholds"`
}

var (
	ifaceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)
	unitName  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,95}\.service$`)
)

func LoadConfig(path string) (Config, error) {
	cfg := Config{Thresholds: thresholds{Fast: 300_000_000, Slow: 1_000_000_000, Sustained: 1_500_000_000}}
	body, err := readBoundedFile(path, 64<<10)
	if err != nil {
		return cfg, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return cfg, errors.New("expected one JSON config object")
	}
	return cfg, cfg.validate()
}

func (c Config) validate() error {
	if !ifaceName.MatchString(c.Interface) || c.Interface == "lo" {
		return errors.New("select one external network interface")
	}
	if len(c.LocalAddresses) == 0 || len(c.LocalAddresses) > 16 {
		return errors.New("configure one to sixteen local addresses as seen on the selected interface")
	}
	for _, ip := range c.LocalAddresses {
		if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.Zone() != "" {
			return errors.New("invalid local address")
		}
	}
	if c.Thresholds.Fast == 0 || c.Thresholds.Slow == 0 || c.Thresholds.Sustained == 0 ||
		max(c.Thresholds.Fast, c.Thresholds.Slow, c.Thresholds.Sustained) > 1<<50 {
		return errors.New("traffic thresholds must be between 1 byte and 1 PiB")
	}
	if !filepath.IsAbs(c.ScratchDir) || !filepath.IsAbs(c.StateDir) ||
		containsPath(c.ScratchDir, c.StateDir) || containsPath(c.StateDir, c.ScratchDir) {
		return errors.New("scratch_dir and state_dir must be separate absolute directories")
	}
	if c.UploadDir != "" {
		if !filepath.IsAbs(c.UploadDir) {
			return errors.New("upload_dir must be an absolute directory")
		}
		upload, err := filepath.EvalSymlinks(c.UploadDir)
		if err != nil {
			return fmt.Errorf("resolve upload_dir: %w", err)
		}
		for _, dir := range []string{c.ScratchDir, c.StateDir} {
			resolved, err := filepath.EvalSymlinks(dir)
			if errors.Is(err, os.ErrNotExist) {
				resolved = filepath.Clean(dir)
			} else if err != nil {
				return err
			}
			if containsPath(resolved, upload) || containsPath(upload, resolved) {
				return errors.New("upload_dir must be separate from the scratch and state directories")
			}
		}
		info, err := os.Lstat(c.UploadDir)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode().Perm() != 0o750 || info.Mode()&os.ModeSetgid == 0 || int(stat.Uid) != os.Geteuid() {
			return errors.New("upload_dir must be owned by the analyzer with mode 2750")
		}
	}
	seen := make(map[string]bool)
	if len(c.Services) > 8 {
		return errors.New("configure at most eight accounted services")
	}
	for _, service := range c.Services {
		if !unitName.MatchString(service.Unit) || seen[service.Unit] {
			return errors.New("invalid or duplicate systemd service unit")
		}
		switch service.Group {
		case "system_update", "backup", "other_proxy":
		default:
			return errors.New("service group must be system_update, backup or other_proxy")
		}
		seen[service.Unit] = true
	}
	if c.Xray != nil {
		return c.Xray.validate()
	}
	return nil
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("expected a regular file within the byte limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeds byte limit")
	}
	return data, err
}

func containsPath(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

func privateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0o700 || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%s must be a directory owned by the analyzer with mode 0700", path)
	}
	return nil
}

func checkScratch(path string) error {
	if err := privateDirectory(path); err != nil {
		return err
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		return err
	}
	if fs.Type != unix.TMPFS_MAGIC || fs.Blocks*uint64(fs.Bsize) > 64<<20 {
		return errors.New("scratch_dir must be on a tmpfs limited to at most 64 MiB")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	var match string
	var noSwap bool
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, "\\")
	for _, line := range strings.Split(string(mounts), "\n") {
		left, right, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		fields, super := strings.Fields(left), strings.Fields(right)
		if len(fields) < 5 || len(super) < 3 {
			continue
		}
		mount := replacer.Replace(fields[4])
		if len(mount) >= len(match) && containsPath(mount, resolved) {
			match = mount
			noSwap = super[0] == "tmpfs" && strings.Contains(","+super[2]+",", ",noswap,")
		}
	}
	if !noSwap {
		return errors.New("scratch tmpfs must be mounted with noswap")
	}
	return nil
}
