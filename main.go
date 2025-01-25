package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"syscall"
	"time"

	"probpf/monitor"

	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	var (
		ifaceName        string
		enablePrometheus bool
		prometheusAddr   string
		syncInterval     int
		xdpMode          string
	)

	flag.StringVar(&ifaceName, "i", "br0", "Interface to monitor")
	flag.BoolVar(&enablePrometheus, "prometheus", false, "Enable Prometheus metrics")
	flag.StringVar(&prometheusAddr, "addr", ":9092", "Prometheus metrics address")
	flag.IntVar(&syncInterval, "s", 5, "Stats sync interval in seconds")
	flag.StringVar(&xdpMode, "x", "generic", "XDP mode (auto, generic, driver, offload)")
	flag.Parse()

	var xdpAttachFlags link.XDPAttachFlags = 0
	switch xdpMode {
	case "auto":
		xdpAttachFlags = 0
	case "generic":
		xdpAttachFlags = link.XDPGenericMode
	case "driver":
		xdpAttachFlags = link.XDPDriverMode
	case "offload":
		xdpAttachFlags = link.XDPOffloadMode
	default:
		xdpAttachFlags = link.XDPGenericMode
	}

	if ifaceName == "" {
		fmt.Println("Please specify interface with -i")
		os.Exit(1)
	}

	currentUser, err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting current user: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Starting monitor...")

	m, err := monitor.NewMonitor(ifaceName, currentUser.Username, xdpAttachFlags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating monitor: %v\n", err)
		os.Exit(1)
	}
	defer m.Close()

	// 首次更新数据
	m.UpdateStats()

	if enablePrometheus {
		collector := monitor.NewPrometheusCollector(m)
		prometheus.MustRegister(collector)

		http.Handle("/metrics", promhttp.Handler())
		server := &http.Server{
			Addr:    prometheusAddr,
			Handler: nil,
		}

		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Fprintf(os.Stderr, "Error starting Prometheus server: %v\n", err)
				os.Exit(1)
			}
		}()
		fmt.Printf("Prometheus metrics server started at %s\n", prometheusAddr)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(time.Duration(syncInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 统一在这里更新数据
			m.UpdateStats()
			// 如果是 CLI 模式，显示数据
			if !enablePrometheus {
				m.PrintStats()
			}
		case <-sigChan:
			fmt.Println("\nShutting down...")
			return
		}
	}
}
