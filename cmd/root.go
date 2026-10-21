package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"time"

	"github.com/komari-monitor/komari-agent/dnsresolver"
	"github.com/komari-monitor/komari-agent/monitoring/netstatic"
	monitoring "github.com/komari-monitor/komari-agent/monitoring/unit"
	"github.com/komari-monitor/komari-agent/update"
	"github.com/spf13/cobra"

	"github.com/komari-monitor/komari-agent/clientcore"
	pkg_flags "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/capability"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/core/privileged"
	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
	"github.com/komari-monitor/komari-agent/core/statelock"
)

var flags = pkg_flags.GlobalConfig

var RootCmd = &cobra.Command{
	Use:   "komari-agent",
	Short: "komari agent",
	Long:  `komari agent`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		installedService, err = readServiceConfig(executable)
		if err != nil {
			return err
		}
		installedService.apply(flags)
		if installedService != nil {
			flags.ServiceManifestFile = installedService.ManifestPath
		}
		forceDeny := flags.DisableRemoteControl
		loadFromEnv()
		forceDeny = forceDeny || flags.DisableRemoteControl
		// Subcommands use the same bootstrap configuration as the daemon.
		if flags.ConfigFile != "" {
			data, err := os.ReadFile(flags.ConfigFile)
			if err != nil {
				return fmt.Errorf("read config file: %w", err)
			}
			var decodeErr error
			if installedService != nil && installedService.Version == hostops.ManifestVersion && (flags.ConfigFile == installedService.ConfigFile || flags.ConfigFile == filepath.Join(filepath.Dir(installedService.Executable), "host-bootstrap.json")) {
				if err := hostops.TrustedPath(flags.ConfigFile); err != nil {
					return err
				}
				decodeErr = json.Unmarshal(data, flags)
			} else {
				decodeErr = pkg_flags.DecodeLocalConfig(data, flags)
			}
			if decodeErr != nil {
				return fmt.Errorf("parse config file: %w", decodeErr)
			}
		}
		flags.DisableRemoteControl = flags.DisableRemoteControl || forceDeny
		return nil
	},
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if flags.PreferIPVersion != "" && flags.PreferIPVersion != "4" && flags.PreferIPVersion != "6" {
			return fmt.Errorf("invalid --prefer-ip-version value %q: expected 4 or 6", flags.PreferIPVersion)
		}
		if (flags.CFAccessClientID == "") != (flags.CFAccessClientSecret == "") {
			return errors.New("Cloudflare Access client ID and client secret must be configured together")
		}
		privPath := flags.PrivilegedStateFile
		if privPath == "" {
			privPath = privileged.DefaultPath()
		}
		release, err := statelock.Acquire(privPath + ".daemon.lock")
		if err != nil {
			return err
		}
		defer release()
		runtimePath := flags.RuntimeStateFile
		if runtimePath == "" {
			runtimePath = runtimeconfig.DefaultStatePath()
		}
		releaseRuntime, err := statelock.Acquire(runtimePath + ".daemon.lock")
		if err != nil {
			return err
		}
		defer releaseRuntime()
		runtimeStore, err := runtimeconfig.New(runtimeconfig.FromFlags(flags), flags.RuntimeStateFile)
		if err != nil {
			return fmt.Errorf("failed to initialize runtime config: %w", err)
		}
		runtimeconfig.SetActive(runtimeStore)
		privStore, err := privileged.Open(flags.PrivilegedStateFile)
		if err != nil {
			return fmt.Errorf("load privileged state: %w", err)
		}
		privileged.SetActive(privStore)
		// 捕获中止信号，优雅退出
		stopCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		go func() {
			<-stopCtx.Done()
			log.Printf("shutting down gracefully...")
			netstatic.Stop()
		}()

		if flags.ShowWarning {
			ShowToast()
			os.Exit(0)
		}

		if allowed, _ := capability.RemoteControlAllowed(runtimeconfig.RemoteControlEnabled()); allowed {
			go WarnKomariRunning()
		}

		if flags.MonthRotate != 0 {
			err := netstatic.StartOrContinue()
			if err != nil {
				log.Println("Failed to start netstatic monitoring:", err)
			}
			nics, err := monitoring.InterfaceList()
			if err != nil {
				log.Println("Failed to get interface list for netstatic:", err)
			}
			err = netstatic.SetNewConfig(netstatic.NetStaticConfig{
				Nics: nics,
			})
			if err != nil {
				log.Println("Failed to set netstatic config:", err)
			}
		}

		log.Println("Komari Agent", update.CurrentVersion)
		log.Println("Github Repo:", update.Repo)

		// 设置 DNS 解析行为
		if flags.CustomDNS != "" {
			dnsresolver.SetCustomDNSServer(flags.CustomDNS)
			log.Printf("Using custom DNS server: %s", flags.CustomDNS)
		} else {
			// 未设置则使用系统默认 DNS（不使用内置列表）
			log.Printf("Using system default DNS resolver")
		}

		// Auto discovery
		if flags.AutoDiscoveryKey != "" {
			err := handleAutoDiscovery()
			if err != nil {
				return fmt.Errorf("auto-discovery failed: %w", err)
			}
		}
		diskList, err := monitoring.DiskList()
		if err != nil {
			log.Println("Failed to get disk list:", err)
		}
		log.Println("Monitoring Mountpoints:", diskList)
		interfaceList, err := monitoring.InterfaceList()
		if err != nil {
			log.Println("Failed to get interface list:", err)
		}
		log.Println("Monitoring Interfaces:", interfaceList)

		// 自动更新
		if !flags.DisableAutoUpdate {
			err := update.CheckAndUpdate()
			if err != nil {
				log.Println("[ERROR]", err)
			}
			go update.DoUpdateWorks()
		}
		// restarts counts consecutive session rebuilds. Rebuilding replays the
		// whole handshake, so a panel that keeps ending sessions must be backed
		// off rather than re-dialled on a fixed period: the latter is what makes
		// one unhealthy Agent look like a scanner to a log-driven IP ban layer.
		restarts := 0
		for {
			sessionStart := time.Now()
			connectClient, err := clientcore.New(flags, runtimeStore)
			if err == nil {
				err = connectClient.Run(stopCtx)
			}
			if shouldExit, exitErr := handleSessionOutcome(err); shouldExit {
				return exitErr
			}
			// A session that ran for a useful stretch was healthy, whatever
			// ended it. Only rapid consecutive failures escalate.
			if time.Since(sessionStart) >= time.Minute {
				restarts = 0
			}
			restarts++
			select {
			case <-stopCtx.Done():
				return nil
			case <-time.After(clientcore.RestartDelay(restarts)):
			}
		}
	},
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func init() {
	pkg_flags.RegisterLocalFlags(RootCmd.PersistentFlags(), flags)
	RootCmd.PersistentFlags().StringVar(&serviceManifestPath, "service-manifest", "", "Explicit installed service manifest (shared by all commands)")
	RootCmd.PersistentFlags().BoolVar(&standaloneMode, "standalone", false, "Use standalone bootstrap paths when no installed service manifest exists")
}

func loadFromEnv() {
	val := reflect.ValueOf(flags).Elem()
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		// Get the env tag
		envTag := fieldType.Tag.Get("env")
		if envTag == "" {
			continue
		}

		// Get the environment variable value
		envValue := os.Getenv(envTag)
		if envValue == "" {
			continue
		}

		// Set the field based on its type
		switch field.Kind() {
		case reflect.String:
			field.SetString(envValue)
		case reflect.Bool:
			if value, err := strconv.ParseBool(envValue); err == nil {
				field.SetBool(value)
			}
		case reflect.Int:
			if intVal, err := strconv.Atoi(envValue); err == nil {
				field.SetInt(int64(intVal))
			}
		case reflect.Float64:
			if floatVal, err := strconv.ParseFloat(envValue, 64); err == nil {
				field.SetFloat(floatVal)
			}
		}
	}
}

// handleSessionOutcome decides whether an error returned by clientcore should
// cause the daemon to exit immediately or be retried with exponential backoff.
//
// Transient transport failures (such as server restart, network drop, timeout,
// or connect.CodeUnavailable wrapped into ErrLegacyFallback) must never cause
// the daemon to exit.
func handleSessionOutcome(err error) (shouldExit bool, exitErr error) {
	if errors.Is(err, clientcore.ErrUnconfigured) {
		log.Printf("Connect agent cannot start: %v", err)
		return true, err
	}
	if errors.Is(err, clientcore.ErrPermissionDenied) {
		log.Printf("Connect agent credentials revoked (HTTP 403 / PERMISSION_DENIED): %v. Please re-enroll via 'komari-agent login'", err)
		return true, err
	}
	if errors.Is(err, clientcore.ErrLegacyFallback) {
		log.Printf("Connect endpoint temporarily unavailable (will retry with backoff): %v", err)
		return false, nil
	}
	if err != nil {
		log.Printf("Connect agent transport stopped (will retry with backoff): %v", err)
		return false, nil
	}
	return false, nil
}
