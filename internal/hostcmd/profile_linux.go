//go:build linux

package hostcmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	flags "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/hostops"
)

// Parse legacy service arguments only as data. This migration parser remains
// private to the host tool when the public daemon CLI is reduced later.
func captureBootstrap(m *hostops.Manifest, o serviceObservation, t *hostops.Trust) (*flags.Config, error) {
	args, err := parseExecStart(o.ExecStart)
	if err != nil {
		return nil, err
	}
	if args[0] != m.Executable {
		return nil, errors.New("service executable differs from trusted manifest")
	}
	c, err := parseLegacyBootstrap(args)
	if err != nil {
		return nil, err
	}
	// Environment files can carry additional unreviewed bootstrap paths and
	// secrets. Refuse instead of copying untrusted shell/environment into root.
	env, err := systemctl("show", m.ServiceName, "--property=Environment,EnvironmentFiles,PassEnvironment")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(env, "\n") {
		_, val, ok := strings.Cut(line, "=")
		if ok && val != "" {
			return nil, errors.New("service environment overrides must be migrated into a reviewed bootstrap before host conversion")
		}
	}
	c.Endpoint = t.Endpoint
	return c, nil
}

// parseLegacyBootstrap is used only by the administrator's offline migration.
// Retired flags are never registered on the public daemon CLI.
func parseLegacyBootstrap(args []string) (*flags.Config, error) {
	c := &flags.Config{Interval: 3, InfoReportInterval: 5, ReconnectInterval: 5, MaxRetries: 3}
	v := reflect.ValueOf(c).Elem()
	typ := v.Type()
	fields := map[string]int{}
	for i := 0; i < typ.NumField(); i++ {
		key := typ.Field(i).Tag.Get("json")
		if key != "" && key != "-" {
			fields[strings.ReplaceAll(key, "_", "-")] = i
		}
	}
	for alias, field := range map[string]string{"include-mountpoint": "include-mountpoints", "auto-discovery": "auto-discovery-key", "config": "config-file", "gpu": "enable-gpu"} {
		fields[alias] = fields[field]
	}
	for i := 1; i < len(args); i++ {
		key, value, has := strings.Cut(args[i], "=")
		if len(key) == 2 && strings.HasPrefix(key, "-") {
			if name, ok := map[string]string{"e": "endpoint", "t": "token", "i": "interval", "r": "max-retries", "u": "ignore-unsafe-cert", "c": "reconnect-interval"}[key[1:]]; ok {
				key = "--" + name
			}
		}
		if key == "--service-manifest" {
			if !has {
				i++
				if i >= len(args) {
					return nil, errors.New("missing manifest argument")
				}
			}
			continue
		}
		index, ok := fields[strings.TrimPrefix(key, "--")]
		if !ok || !strings.HasPrefix(key, "--") {
			return nil, errors.New("unsupported legacy service argument; migrate to an explicit reviewed JSON bootstrap")
		}
		f := v.Field(index)
		if !has {
			if f.Kind() == reflect.Bool {
				value = "true"
			} else {
				i++
				if i >= len(args) {
					return nil, errors.New("missing legacy service argument")
				}
				value = args[i]
			}
		}
		switch f.Kind() {
		case reflect.String:
			f.SetString(value)
		case reflect.Bool:
			b, e := strconv.ParseBool(value)
			if e != nil {
				return nil, e
			}
			f.SetBool(b)
		case reflect.Int:
			n, e := strconv.Atoi(value)
			if e != nil {
				return nil, e
			}
			f.SetInt(int64(n))
		case reflect.Float64:
			n, e := strconv.ParseFloat(value, 64)
			if e != nil {
				return nil, e
			}
			f.SetFloat(n)
		}
	}
	localDeny := c.DisableRemoteControl
	if c.ConfigFile != "" {
		data, err := hostops.ReadCandidate(c.ConfigFile)
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal(data, c); err != nil {
			return nil, err
		}
	}
	c.DisableRemoteControl = c.DisableRemoteControl || localDeny
	return c, nil
}

func verifyService(service string, wantUID int, mode int32) error {
	// Require the same process to remain alive through several observations;
	// a successful ExecStart followed by an immediate crash is not success.
	previous := ""
	stable := 0
	for attempt := 0; attempt < 30; attempt++ {
		o, err := observe(service)
		if err == nil && o.MainPID != "0" && o.MainPID != "" {
			b, e := os.ReadFile("/proc/" + o.MainPID + "/status")
			if e == nil {
				values := map[string]string{}
				for _, line := range strings.Split(string(b), "\n") {
					k, v, ok := strings.Cut(line, ":")
					if ok {
						values[k] = strings.TrimSpace(v)
					}
				}
				uidFields := strings.Fields(values["Uid"])
				valid := len(uidFields) == 4
				for _, uid := range uidFields {
					valid = valid && uid == strconv.Itoa(wantUID)
				}
				bound, _ := strconv.ParseUint(values["CapBnd"], 16, 64)
				eff, _ := strconv.ParseUint(values["CapEff"], 16, 64)
				if mode == 1 {
					const required = uint64(1<<0 | 1<<1 | 1<<6 | 1<<7 | 1<<12 | 1<<13 | 1<<21 | 1<<22)
					valid = valid && values["NoNewPrivs"] == "0" && bound&required == required && eff&required == required
				} else {
					valid = valid && values["NoNewPrivs"] == "1" && bound == 1<<13
				}
				if valid {
					if o.MainPID == previous {
						stable++
					} else {
						stable = 1
						previous = o.MainPID
					}
					if stable >= 3 {
						return nil
					}
				} else {
					stable = 0
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("service %s did not reach verified UID=%d capability/NoNewPrivileges profile", service, wantUID)
}
func waitHelper(m *hostops.Manifest) error {
	for i := 0; i < 60; i++ {
		status, err := hostops.ReadHelperStatus(m)
		if err == nil && status.Authorized && status.LeaseReady {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("helper is installed but not authorized/connected; startup has not reached lease-ready")
}
