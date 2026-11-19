package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// AutoDiscoveryConfig stores a legacy pre-existing auto-discovery token file.
type AutoDiscoveryConfig struct {
	UUID  string `json:"uuid"`
	Token string `json:"token"`
}

var (
	errLegacyAutoDiscoveryRemoved = errors.New("legacy /api/clients/register auto-discovery has been removed; enroll this agent using device enrollment instead")
	chmodAutoDiscoveryFile        = os.Chmod
)

// getAutoDiscoveryFilePath returns the legacy auto-discovery config file path.
func getAutoDiscoveryFilePath() string {
	if configured := strings.TrimSpace(os.Getenv("AGENT_AUTO_DISCOVERY_FILE")); configured != "" {
		return configured
	}
	execPath, err := os.Executable()
	if err != nil {
		log.Println("Failed to get executable path:", err)
		return "auto-discovery.json"
	}
	execDir := filepath.Dir(execPath)
	return filepath.Join(execDir, "auto-discovery.json")
}

// loadAutoDiscoveryConfig loads an existing legacy auto-discovery config file
// (if present) and tightens its permissions to 0600 so existing 0644 files do
// not continue exposing tokens to other local users.
func loadAutoDiscoveryConfig() (*AutoDiscoveryConfig, error) {
	configPath := getAutoDiscoveryFilePath()

	info, err := os.Stat(configPath)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to stat auto-discovery config: %w", err)
	}

	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			if err := chmodAutoDiscoveryFile(configPath, 0o600); err != nil {
				return nil, fmt.Errorf("auto-discovery config %s has overly permissive mode %04o and failed to tighten to 0600: %w", configPath, perm, err)
			}
		}
	} else if err := chmodAutoDiscoveryFile(configPath, 0o600); err != nil {
		log.Printf("Warning: failed to tighten permissions on %s: %v", configPath, err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read auto-discovery config: %w", err)
	}

	var config AutoDiscoveryConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse auto-discovery config: %w", err)
	}
	if strings.TrimSpace(config.Token) == "" {
		return nil, errors.New("auto-discovery config contains an empty token")
	}

	return &config, nil
}

// handleAutoDiscovery preserves read-only loading of pre-existing legacy
// auto-discovery configs while refusing new registrations against the removed
// /api/clients/register endpoint.
func handleAutoDiscovery() error {
	config, err := loadAutoDiscoveryConfig()
	if err != nil {
		return err
	}
	if config != nil {
		flags.Token = config.Token
		log.Printf("Using existing auto-discovery token for UUID: %s", config.UUID)
		return nil
	}
	return errLegacyAutoDiscoveryRemoved
}
