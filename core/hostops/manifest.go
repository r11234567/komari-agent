// Package hostops owns administrator-managed installation metadata. It never
// treats daemon-writable candidates as permission to run a host operation.
package hostops

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const ManifestVersion = 2
const Registry = "/etc/komari/services"

type Manifest struct {
	Version             int    `json:"version,omitempty"`
	ServiceName         string `json:"service_name"`
	ServiceUser         string `json:"service_user"`
	InitSystem          string `json:"init_system"`
	Executable          string `json:"executable,omitempty"`
	HostTool            string `json:"host_tool,omitempty"`
	HostPolicyFile      string `json:"host_policy_file,omitempty"`
	ConfigFile          string `json:"config_file,omitempty"`
	CredentialsFile     string `json:"credentials_file"`
	RuntimeStateFile    string `json:"runtime_state_file"`
	PrivilegedStateFile string `json:"privileged_state_file"`
	ReplayStateFile     string `json:"replay_state_file"`
	ManifestPath        string `json:"-"`
}

// Policy is never writable by the daemon. Baseline describes existing local
// authorization; Allow limits future panel approvals without changing OS identity.
type Policy struct {
	Version                int    `json:"version"`
	ServiceID              string `json:"service_id"`
	PrivilegeMode          int32  `json:"privilege_mode"`
	AllowRemoteControl     bool   `json:"allow_remote_control"`
	AllowWebSSH            bool   `json:"allow_webssh"`
	AllowExecution         bool   `json:"allow_execution"`
	AllowGPU               bool   `json:"allow_gpu"`
	ForceDenyRemoteControl bool   `json:"force_deny_remote_control"`
	BaselineRemoteControl  bool   `json:"baseline_remote_control"`
	BaselineWebSSH         bool   `json:"baseline_webssh"`
	BaselineExecution      bool   `json:"baseline_execution"`
	BaselineGPU            bool   `json:"baseline_gpu"`
	AllowRescueHelper      bool   `json:"allow_rescue_helper"`
	HelperAuthorized       bool   `json:"helper_authorized"`
	HelperInstalled        bool   `json:"helper_installed"`
	DisableSource          string `json:"disable_source"`
}

func ReadJSON(path string, target any, trusted bool) error {
	if trusted {
		if err := TrustedPath(path); err != nil {
			return err
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return errors.New("invalid metadata file type or size")
	}
	dec := json.NewDecoder(io.LimitReader(file, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("metadata has trailing content")
	}
	return nil
}

func ReadManifest(path string) (*Manifest, error) {
	var m Manifest
	if err := ReadJSON(path, &m, false); err != nil {
		return nil, err
	}
	if m.Version >= ManifestVersion {
		if err := TrustedPath(path); err != nil {
			return nil, err
		}
	}
	m.ManifestPath = path
	dir := filepath.Dir(path)
	for _, p := range []*string{&m.Executable, &m.HostTool, &m.HostPolicyFile, &m.ConfigFile, &m.CredentialsFile, &m.RuntimeStateFile, &m.PrivilegedStateFile, &m.ReplayStateFile} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(dir, *p)
		}
	}
	return &m, nil
}

func ReadPolicy(m *Manifest) (*Policy, error) {
	if m == nil || m.Version != ManifestVersion || m.HostPolicyFile == "" {
		return nil, errors.New("trusted installation policy missing; run komari-host migrate")
	}
	var p Policy
	if err := ReadJSON(m.HostPolicyFile, &p, true); err != nil {
		return nil, err
	}
	if p.Version != ManifestVersion || p.ServiceID != m.ServiceName {
		return nil, errors.New("host policy does not match installed service")
	}
	return &p, nil
}

func ValidService(name string) bool {
	if name == "" || len(name) > 128 || strings.HasPrefix(name, "-") {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.-", c)) {
			return false
		}
	}
	return true
}

func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("refusing non-regular destination %s", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".komari-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func WriteJSON(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return AtomicWrite(path, append(data, '\n'), mode)
}
