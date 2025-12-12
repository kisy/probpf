package config

import (
	"fmt"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/cilium/ebpf/link"
)

// Duration wraps time.Duration to support TOML unmarshaling
type Duration struct {
	time.Duration
}

// UnmarshalText implements encoding.TextUnmarshaler for TOML parsing
func (d *Duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}

// Config represents the application configuration
type Config struct {
	Interface      string   `toml:"interface"`
	HTTPAddr       string   `toml:"http_addr"`
	SyncInterval   Duration `toml:"sync_interval"`
	BpfTTL         Duration `toml:"bpf_ttl"`
	FlowTTL        Duration `toml:"flow_ttl"`
	ClientCacheTTL Duration `toml:"client_ttl"`
	XDPMode        string   `toml:"xdp_mode"`
	Hostname       map[string]string
	IgnoreLan      bool     `toml:"ignore_lan"` // Default true
	LanCIDRs       []string `toml:"lan_cidrs"`  // CIDR strings
}

func DefaultConfig() Config {
	return Config{
		Interface:      "br0",
		HTTPAddr:       "",
		SyncInterval:   Duration{2 * time.Second},   // bpf -> go sync interval
		BpfTTL:         Duration{60 * time.Second},  // bpf map cleanup interval
		FlowTTL:        Duration{600 * time.Second}, // Keep flows for 10m
		ClientCacheTTL: Duration{120 * time.Second}, // Cache client details for 2m
		XDPMode:        "generic",
		Hostname:       map[string]string{},
		IgnoreLan:      true,
		LanCIDRs:       []string{},
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

// ApplySmartDefaults auto-derives bpf-ttl and client-ttl from flow-ttl if not explicitly set
func (c *Config) ApplySmartDefaults() {
	// If BpfTTL is 0 or not set, derive from FlowTTL
	// BPF cleanup should run at 1/5 of flow timeout to ensure timely cleanup
	if c.BpfTTL.Duration <= 0 {
		c.BpfTTL.Duration = max(c.FlowTTL.Duration/5, 10*time.Second)
	}

	// If ClientCacheTTL is 0 or not set, derive from FlowTTL
	// Cache for 2/5 of flow timeout (typically half the flow lifetime)
	if c.ClientCacheTTL.Duration <= 0 {
		c.ClientCacheTTL.Duration = max(c.FlowTTL.Duration*2/5, 5*time.Second)
	}
}
