package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kisy/probpf/config"
	"github.com/kisy/probpf/pkg/bpf"
	"github.com/kisy/probpf/pkg/stats"
	"github.com/kisy/probpf/pkg/web"
)

// stringSlice allows multiple -cidr flags
type stringSlice []string

func (s *stringSlice) String() string {
	return fmt.Sprintf("%v", *s)
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	var (
		cfgFile string
		cfg     config.Config
	)

	defaultCfg := config.DefaultConfig()
	cfg = defaultCfg

	// Define command-line flags
	var monitorLAN bool
	var cidrFlags stringSlice

	// Config file
	flag.StringVar(&cfgFile, "c", "", "Path to TOML configuration file")
	flag.StringVar(&cfgFile, "config", "", "Path to TOML configuration file (alias)")

	// Network interface
	flag.StringVar(&cfg.Interface, "i", defaultCfg.Interface, "Network interface to monitor")
	flag.StringVar(&cfg.Interface, "interface", defaultCfg.Interface, "Network interface to monitor (alias)")

	// HTTP server
	flag.StringVar(&cfg.HTTPAddr, "l", defaultCfg.HTTPAddr, "Web server listen address (e.g., :8080)")
	flag.StringVar(&cfg.HTTPAddr, "listen", defaultCfg.HTTPAddr, "Web server listen address (alias)")
	flag.StringVar(&cfg.HTTPAddr, "http", defaultCfg.HTTPAddr, "Web server listen address (alias)")

	// Intervals and timeouts
	flag.DurationVar(&cfg.SyncInterval.Duration, "s", defaultCfg.SyncInterval.Duration, "Data sync interval")
	flag.DurationVar(&cfg.SyncInterval.Duration, "sync-interval", defaultCfg.SyncInterval.Duration, "Data sync interval (alias)")

	flag.DurationVar(&cfg.BpfTTL.Duration, "bpf-ttl", defaultCfg.BpfTTL.Duration, "BPF map cleanup interval")
	flag.DurationVar(&cfg.BpfTTL.Duration, "gc", defaultCfg.BpfTTL.Duration, "BPF map cleanup interval (deprecated, use --bpf-ttl)")

	flag.DurationVar(&cfg.FlowTTL.Duration, "flow-ttl", defaultCfg.FlowTTL.Duration, "Inactive flow timeout")

	flag.DurationVar(&cfg.ClientCacheTTL.Duration, "client-ttl", defaultCfg.ClientCacheTTL.Duration, "Client detail cache duration")

	// XDP mode
	flag.StringVar(&cfg.XDPMode, "x", defaultCfg.XDPMode, "XDP mode: auto, generic, driver, offload")
	flag.StringVar(&cfg.XDPMode, "xdp-mode", defaultCfg.XDPMode, "XDP mode: auto, generic, driver, offload (alias)")

	// LAN monitoring
	flag.BoolVar(&monitorLAN, "lan", false, "Monitor LAN traffic (disable local traffic filtering)")
	flag.BoolVar(&monitorLAN, "monitor-lan", false, "Monitor LAN traffic (alias)")

	// Local CIDR filtering
	flag.Var(&cidrFlags, "cidr", "Local CIDR to ignore (can be specified multiple times)")
	flag.Var(&cidrFlags, "local-cidr", "Local CIDR to ignore (alias)")

	flag.Parse()

	// Load configuration
	if cfgFile != "" {
		if err := config.LoadConfig(cfgFile, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}
	}

	// Merge flags into config
	if monitorLAN {
		cfg.IgnoreLan = false
	}
	if len(cidrFlags) > 0 {
		cfg.LanCIDRs = append(cfg.LanCIDRs, cidrFlags...)
	}

	// Validate and apply smart defaults
	if cfg.FlowTTL.Duration <= 0 {
		cfg.FlowTTL = defaultCfg.FlowTTL
	}

	// Apply smart defaults: auto-derive gc-ttl and client-ttl from flow-ttl
	cfg.ApplySmartDefaults()

	if cfg.Interface == "" {
		fmt.Println("Please specify interface with -i flag or in config file")
		os.Exit(1)
	}

	// Auto-detect CIDRs if enabled (IgnoreLan=true) and no CIDRs specified
	if cfg.IgnoreLan && len(cfg.LanCIDRs) == 0 {
		iface, err := net.InterfaceByName(cfg.Interface)
		if err != nil {
			fmt.Printf("Warning: Failed to get interface %s for auto-detection: %v\n", cfg.Interface, err)
		} else {
			addrs, err := iface.Addrs()
			if err != nil {
				fmt.Printf("Warning: Failed to get addresses for interface %s: %v\n", cfg.Interface, err)
			} else {
				for _, addr := range addrs {
					// Addrs() returns *net.IPNet which is exactly what we want (CIDR)
					if ipnet, ok := addr.(*net.IPNet); ok {
						// Skip link-local if desired? No, usually fine to include.
						// Just append the string representation
						cfg.LanCIDRs = append(cfg.LanCIDRs, ipnet.String())
						fmt.Printf("Auto-detected local CIDR: %s\n", ipnet.String())
					}
				}
			}
		}
	}

	// Parse Local CIDRs
	var parsedCIDRs []*net.IPNet
	if cfg.IgnoreLan {
		for _, nonParsed := range cfg.LanCIDRs {
			_, ipnet, err := net.ParseCIDR(nonParsed)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing CIDR %s: %v\n", nonParsed, err)
				os.Exit(1)
			}
			parsedCIDRs = append(parsedCIDRs, ipnet)
		}
		if len(parsedCIDRs) > 0 {
			fmt.Printf("Ignoring local traffic in: %v\n", cfg.LanCIDRs)
		} else {
			if !monitorLAN {
				// Warn if user wanted to ignore LAN but we found no CIDRs?
				// Or maybe usage without CIDR implies no filtering (which contradicts default).
				// We'll leave it as is: empty list means nothing is ignored.
				fmt.Println("Warning: No local CIDRs detected or specified. LAN filtering is active but effective list is empty (monitoring everything).")
			}
		}
	} else {
		fmt.Println("LAN monitoring enabled (capturing all traffic)")
	}

	// Print Effective Configuration
	fmt.Println("---------------------------------------------------------")
	fmt.Printf("ProBPF Configuration:\n")
	fmt.Printf("  Interface:    %s\n", cfg.Interface)
	fmt.Printf("  Web Server:   http://%s/clients\n", cfg.HTTPAddr)
	fmt.Printf("  Sync Interval: %v\n", cfg.SyncInterval)
	fmt.Printf("  Flow Timeout:  %v (--flow-ttl)\n", cfg.FlowTTL)
	fmt.Printf("  BPF Cleanup:   %v (--bpf-ttl, auto: flow-ttl/5)\n", cfg.BpfTTL)
	fmt.Printf("  Client Cache:  %v (auto: flow-ttl*0.4)\n", cfg.ClientCacheTTL)
	fmt.Printf("  Ignore LAN:   %v\n", cfg.IgnoreLan)
	if cfg.IgnoreLan {
		if len(cfg.LanCIDRs) > 0 {
			fmt.Printf("  Local CIDRs:  %v\n", cfg.LanCIDRs)
		} else {
			fmt.Printf("  Local CIDRs:  (None detected - Warning: Traffic might not be filtered)\n")
		}
	}
	fmt.Println("---------------------------------------------------------")

	fmt.Printf("Starting probpf on interface %s...\n", cfg.Interface)

	// Initializes System Components
	// 1. Loading BPF
	loader, err := bpf.Load(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading BPF: %v\n", err)
		os.Exit(1)
	}
	defer loader.Close()

	// 2. Initialize Stats Aggregator
	aggregator := stats.NewAggregator(loader, cfg.Hostname)
	aggregator.SetLocalFiltering(cfg.IgnoreLan, parsedCIDRs)
	aggregator.SetConfig(cfg.BpfTTL.Duration, cfg.FlowTTL.Duration)
	aggregator.SetClientCacheTTL(cfg.ClientCacheTTL.Duration)

	// 3. Initialize Web Server
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = ":9092"
	}

	webServer := web.NewServer(aggregator)
	webServer.RegisterHandlers()

	go func() {
		if err := http.ListenAndServe(cfg.HTTPAddr, nil); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting Web server: %v\n", err)
		}
	}()
	fmt.Printf("Web UI available at http://%s/clients\n", cfg.HTTPAddr)

	// Main Loop
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(cfg.SyncInterval.Duration)
	defer ticker.Stop()

	// Initial Update
	if err := aggregator.Update(); err != nil {
		fmt.Fprintf(os.Stderr, "Error updating stats: %v\n", err)
	}

	// Cleaner Loop removed (integrated into Aggregator.Update)

	for {
		select {
		case <-ticker.C:
			if err := aggregator.Update(); err != nil {
				fmt.Fprintf(os.Stderr, "Error updating stats: %v\n", err)
			}

		case <-sigChan:
			fmt.Println("\nShutting down...")
			return
		}
	}
}
