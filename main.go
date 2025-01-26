package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/kisy/probpf/config"
	"github.com/kisy/probpf/monitor"
)

func main() {
	var (
		cfgFile string
		cfg     config.Config
	)

	defaultCfg := config.DefaultConfig()

	// Define command-line flags
	flag.StringVar(&cfgFile, "c", "", "Path to TOML configuration file")

	// These flags will override config file settings if specified
	flag.StringVar(&cfg.Interface, "i", defaultCfg.Interface, "Interface to monitor")
	flag.StringVar(&cfg.PrometheusAddr, "p", defaultCfg.PrometheusAddr, "Prometheus metrics address")
	flag.IntVar(&cfg.SyncInterval, "s", defaultCfg.SyncInterval, "Stats sync interval in seconds")
	flag.StringVar(&cfg.XDPMode, "x", defaultCfg.XDPMode, "XDP mode (auto, generic, driver, offload)")
	flag.Parse()

	fmt.Printf("cfgFile: %s\n", cfgFile)

	// Load configuration from file if specified
	if cfgFile != "" {
		fmt.Printf("Loading config from file: %s\n", cfgFile)
		err := config.LoadConfig(cfgFile, &cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Configuration: %+v\n", cfg)

	// Validate interface name
	if cfg.Interface == "" {
		fmt.Println("Please specify interface with -i flag or in config file")
		os.Exit(1)
	}

	if cfg.SyncInterval < 1 {
		fmt.Println("Sync interval must be greater than 0")
		os.Exit(1)
	}

	fmt.Println("Starting monitor...")

	m, err := monitor.NewMonitor(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating monitor: %v\n", err)
		os.Exit(1)
	}
	defer m.Close()

	// 首次更新数据
	m.UpdateStats()

	if cfg.PrometheusAddr != "" {
		collector := monitor.NewPrometheusCollector(m)
		prometheus.MustRegister(collector)

		http.Handle("/metrics", promhttp.Handler())
		server := &http.Server{
			Addr:    cfg.PrometheusAddr,
			Handler: nil,
		}

		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Fprintf(os.Stderr, "Error starting Prometheus server: %v\n", err)
				os.Exit(1)
			}
		}()
		fmt.Printf("Prometheus metrics server started at %s\n", cfg.PrometheusAddr)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(time.Duration(cfg.SyncInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 统一在这里更新数据
			m.UpdateStats()
			// 如果是 CLI 模式，显示数据
			if cfg.PrometheusAddr == "" {
				m.PrintStats()
			}
		case <-sigChan:
			fmt.Println("\nShutting down...")
			return
		}
	}
}
