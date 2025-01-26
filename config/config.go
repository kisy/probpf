package config

import (
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/cilium/ebpf/link"
)

// Config represents the application configuration
type Config struct {
	Interface      string `toml:"interface"`
	PrometheusAddr string `toml:"prometheus_addr"`
	SyncInterval   int    `toml:"sync_interval"`
	XDPMode        string `toml:"xdp_mode"`
	Hostname       map[string]string
}

// DefaultConfig returns default configuration
func DefaultConfig() Config {
	return Config{
		Interface:      "br0",
		PrometheusAddr: "",
		SyncInterval:   5,
		XDPMode:        "generic",
		Hostname:       map[string]string{},
	}
}

func LoadConfig(path string, cfg *Config) error {
	if path != "" {
		_, err := toml.DecodeFile(path, cfg)
		if err != nil {
			return fmt.Errorf("error decoding config file: %v", err)
		}
	}
	fmt.Printf("LoadConfig loaded: %+v\n", cfg)
	return nil
}

func FormatXDPMode(mode string) link.XDPAttachFlags {
	var xdpAttachFlags link.XDPAttachFlags = 0
	if mode == "auto" {
		xdpAttachFlags = 0
	} else if mode == "driver" {
		xdpAttachFlags = link.XDPDriverMode
	} else if mode == "offload" {
		xdpAttachFlags = link.XDPOffloadMode
	} else {
		xdpAttachFlags = link.XDPGenericMode
	}

	return xdpAttachFlags
}
