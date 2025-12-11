package config

import (
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/cilium/ebpf/link"
)

// Config represents the application configuration
type Config struct {
	Interface           string `toml:"interface"`
	HTTPAddr            string `toml:"http_addr"`
	SyncInterval        int    `toml:"sync_interval"`
	GCInterval          int    `toml:"gc_interval"`
	DataTTL             int    `toml:"data_ttl"`
	DetailCacheDuration int    `toml:"detail_cache_duration"`
	XDPMode             string `toml:"xdp_mode"`
	Hostname            map[string]string
	IgnoreLocal         bool     `toml:"ignore_local"` // Default true
	LocalCIDRs          []string `toml:"local_cidrs"`  // CIDR strings
}

// DefaultConfig returns default configuration
func DefaultConfig() Config {
	return Config{
		Interface:           "br0",
		HTTPAddr:            "",
		SyncInterval:        1,
		GCInterval:          60,  // Check every 60s
		DataTTL:             600, // Keep data for 10m
		DetailCacheDuration: 120, // Cache details for 2m
		XDPMode:             "generic",
		Hostname:            map[string]string{},
		IgnoreLocal:         true,
		LocalCIDRs:          []string{},
	}
}

func LoadConfig(path string, cfg *Config) error {
	if path != "" {
		_, err := toml.DecodeFile(path, cfg)
		if err != nil {
			return fmt.Errorf("error decoding config file: %v", err)
		}
	}
	return nil
}

func FormatXDPMode(mode string) link.XDPAttachFlags {
	var xdpAttachFlags link.XDPAttachFlags = 0

	switch mode {
	case "auto":
		xdpAttachFlags = 0
	case "driver":
		xdpAttachFlags = link.XDPDriverMode
	case "offload":
		xdpAttachFlags = link.XDPOffloadMode
	default:
		xdpAttachFlags = link.XDPGenericMode
	}

	return xdpAttachFlags
}
