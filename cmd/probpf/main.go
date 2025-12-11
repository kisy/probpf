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

	flag.StringVar(&cfgFile, "c", "", "Path to TOML configuration file")
	flag.StringVar(&cfg.Interface, "i", defaultCfg.Interface, "Interface to monitor")
	flag.StringVar(&cfg.HTTPAddr, "l", defaultCfg.HTTPAddr, "Web server address")
	flag.IntVar(&cfg.SyncInterval, "s", defaultCfg.SyncInterval, "Stats sync interval in seconds")
	flag.IntVar(&cfg.GCInterval, "gc", defaultCfg.GCInterval, "Garbage collection (GC) interval in seconds")
	flag.IntVar(&cfg.DataTTL, "ttl", defaultCfg.DataTTL, "Data retention time (TTL) in seconds")
	flag.StringVar(&cfg.XDPMode, "x", defaultCfg.XDPMode, "XDP mode (auto, generic, driver, offload)")

	flag.IntVar(&cfg.DetailCacheDuration, "detail_cache", defaultCfg.DetailCacheDuration, "Detail stats cache duration in seconds")

	flag.BoolVar(&monitorLAN, "lan", false, "Monitor LAN traffic (disable local traffic filtering)")
	flag.Var(&cidrFlags, "cidr", "Local CIDR to ignore (can be specified multiple times)")

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
		cfg.IgnoreLocal = false
	}
	if len(cidrFlags) > 0 {
		cfg.LocalCIDRs = append(cfg.LocalCIDRs, cidrFlags...)
	}

	// Validate configuration
	if cfg.GCInterval <= 0 {
		cfg.GCInterval = defaultCfg.GCInterval
	}
	if cfg.DataTTL <= 0 {
		cfg.DataTTL = defaultCfg.DataTTL
	}
	if cfg.DetailCacheDuration <= 0 {
		cfg.DetailCacheDuration = defaultCfg.DetailCacheDuration
	}
	if cfg.Interface == "" {
		fmt.Println("Please specify interface with -i flag or in config file")
		os.Exit(1)
	}

	// Auto-detect CIDRs if enabled (IgnoreLocal=true) and no CIDRs specified
	if cfg.IgnoreLocal && len(cfg.LocalCIDRs) == 0 {
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
						cfg.LocalCIDRs = append(cfg.LocalCIDRs, ipnet.String())
						fmt.Printf("Auto-detected local CIDR: %s\n", ipnet.String())
					}
				}
			}
		}
	}

	// Parse Local CIDRs
	var parsedCIDRs []*net.IPNet
	if cfg.IgnoreLocal {
		for _, nonParsed := range cfg.LocalCIDRs {
			_, ipnet, err := net.ParseCIDR(nonParsed)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing CIDR %s: %v\n", nonParsed, err)
				os.Exit(1)
			}
			parsedCIDRs = append(parsedCIDRs, ipnet)
		}
		if len(parsedCIDRs) > 0 {
			fmt.Printf("Ignoring local traffic in: %v\n", cfg.LocalCIDRs)
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
	fmt.Printf("  Ignore LAN:   %v\n", cfg.IgnoreLocal)
	if cfg.IgnoreLocal {
		if len(cfg.LocalCIDRs) > 0 {
			fmt.Printf("  Local CIDRs:  %v\n", cfg.LocalCIDRs)
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
	aggregator.SetLocalFiltering(cfg.IgnoreLocal, parsedCIDRs)
	aggregator.SetConfig(time.Duration(cfg.GCInterval)*time.Second, time.Duration(cfg.DataTTL)*time.Second)
	aggregator.SetDetailCacheDuration(time.Duration(cfg.DetailCacheDuration) * time.Second)

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

	ticker := time.NewTicker(time.Duration(cfg.SyncInterval) * time.Second)
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
