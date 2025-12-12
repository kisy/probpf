package metrics

import (
	"time"

	"github.com/kisy/probpf/pkg/stats"
	"github.com/prometheus/client_golang/prometheus"
)

// Exporter collects ProBPF stats and exports them as Prometheus metrics
type Exporter struct {
	agg *stats.Aggregator

	// Global metrics
	globalDownloadBps       prometheus.Gauge
	globalUploadBps         prometheus.Gauge
	globalActiveConnections prometheus.Gauge
	globalActiveDevices     prometheus.Gauge
	globalBytesTotal        *prometheus.GaugeVec
	uptimeSeconds           prometheus.Gauge

	// Device-level metrics
	deviceDownloadBps       *prometheus.GaugeVec
	deviceUploadBps         *prometheus.GaugeVec
	deviceActiveConnections *prometheus.GaugeVec
	deviceBytesTotal        *prometheus.GaugeVec
	deviceSessionBytes      *prometheus.GaugeVec

	// Protocol-level metrics
	protocolBytesTotal *prometheus.GaugeVec

	startTime time.Time
}

// NewExporter creates a new Prometheus exporter
func NewExporter(agg *stats.Aggregator) *Exporter {
	return &Exporter{
		agg:       agg,
		startTime: time.Now(),

		// Global metrics
		globalDownloadBps: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probpf_global_download_bps",
			Help: "Global download speed in bits per second",
		}),
		globalUploadBps: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probpf_global_upload_bps",
			Help: "Global upload speed in bits per second",
		}),
		globalActiveConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probpf_global_active_connections",
			Help: "Total number of active connections",
		}),
		globalActiveDevices: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probpf_global_active_devices",
			Help: "Number of active devices",
		}),
		globalBytesTotal: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "probpf_global_bytes_total",
				Help: "Total bytes transferred globally",
			},
			[]string{"direction"}, // "download" or "upload"
		),
		uptimeSeconds: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probpf_uptime_seconds",
			Help: "ProBPF uptime in seconds",
		}),

		// Device-level metrics
		deviceDownloadBps: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "probpf_device_download_bps",
				Help: "Device download speed in bits per second",
			},
			[]string{"mac", "name"},
		),
		deviceUploadBps: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "probpf_device_upload_bps",
				Help: "Device upload speed in bits per second",
			},
			[]string{"mac", "name"},
		),
		deviceActiveConnections: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "probpf_device_active_connections",
				Help: "Number of active connections per device",
			},
			[]string{"mac", "name"},
		),
		deviceBytesTotal: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "probpf_device_bytes_total",
				Help: "Total bytes transferred by device",
			},
			[]string{"mac", "name", "direction"},
		),
		deviceSessionBytes: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "probpf_device_session_bytes",
				Help: "Session bytes transferred by device",
			},
			[]string{"mac", "name", "direction"},
		),

		// Protocol-level metrics
		protocolBytesTotal: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "probpf_protocol_bytes_total",
				Help: "Total bytes by protocol",
			},
			[]string{"protocol", "direction"},
		),
	}
}

// Describe implements prometheus.Collector
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.globalDownloadBps.Describe(ch)
	e.globalUploadBps.Describe(ch)
	e.globalActiveConnections.Describe(ch)
	e.globalActiveDevices.Describe(ch)
	e.globalBytesTotal.Describe(ch)
	e.uptimeSeconds.Describe(ch)

	e.deviceDownloadBps.Describe(ch)
	e.deviceUploadBps.Describe(ch)
	e.deviceActiveConnections.Describe(ch)
	e.deviceBytesTotal.Describe(ch)
	e.deviceSessionBytes.Describe(ch)

	e.protocolBytesTotal.Describe(ch)
}

// Collect implements prometheus.Collector
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	// Reset dynamic metrics (devices may come and go)
	e.deviceDownloadBps.Reset()
	e.deviceUploadBps.Reset()
	e.deviceActiveConnections.Reset()
	e.deviceBytesTotal.Reset()
	e.deviceSessionBytes.Reset()
	e.protocolBytesTotal.Reset()

	// Collect global stats
	globalStats := e.agg.GetGlobalStats()
	e.globalDownloadBps.Set(float64(globalStats.DownloadSpeed * 8)) // Convert to bits
	e.globalUploadBps.Set(float64(globalStats.UploadSpeed * 8))
	e.globalActiveConnections.Set(float64(globalStats.ActiveConnections))
	e.globalBytesTotal.WithLabelValues("download").Set(float64(globalStats.TotalDownload))
	e.globalBytesTotal.WithLabelValues("upload").Set(float64(globalStats.TotalUpload))

	// Collect device stats
	clients := e.agg.GetClients()
	e.globalActiveDevices.Set(float64(len(clients)))

	// Protocol accumulator
	protocolStats := make(map[string]map[string]uint64) // protocol -> direction -> bytes

	for _, client := range clients {
		mac := client.MAC
		name := client.Name
		if name == "" {
			name = mac // Fallback to MAC if no name
		}

		// Device-level metrics
		e.deviceDownloadBps.WithLabelValues(mac, name).Set(float64(client.DownloadSpeed * 8))
		e.deviceUploadBps.WithLabelValues(mac, name).Set(float64(client.UploadSpeed * 8))
		e.deviceActiveConnections.WithLabelValues(mac, name).Set(float64(client.ActiveConnections))
		e.deviceBytesTotal.WithLabelValues(mac, name, "download").Set(float64(client.TotalDownload))
		e.deviceBytesTotal.WithLabelValues(mac, name, "upload").Set(float64(client.TotalUpload))

		// Get session stats
		clientWithSession := e.agg.GetClientWithSession(mac)
		if clientWithSession != nil {
			e.deviceSessionBytes.WithLabelValues(mac, name, "download").Set(float64(clientWithSession.SessionDownload))
			e.deviceSessionBytes.WithLabelValues(mac, name, "upload").Set(float64(clientWithSession.SessionUpload))
		}

		// Collect flow-level stats for protocol breakdown
		flows, _ := e.agg.GetFlowsByMAC(mac)
		for _, flow := range flows {
			if protocolStats[flow.Protocol] == nil {
				protocolStats[flow.Protocol] = make(map[string]uint64)
			}
			protocolStats[flow.Protocol]["download"] += flow.TotalDownload
			protocolStats[flow.Protocol]["upload"] += flow.TotalUpload
		}
	}

	// Export protocol stats
	for protocol, directions := range protocolStats {
		for direction, bytes := range directions {
			e.protocolBytesTotal.WithLabelValues(protocol, direction).Set(float64(bytes))
		}
	}

	// Uptime
	e.uptimeSeconds.Set(time.Since(e.startTime).Seconds())

	// Collect all metrics
	e.globalDownloadBps.Collect(ch)
	e.globalUploadBps.Collect(ch)
	e.globalActiveConnections.Collect(ch)
	e.globalActiveDevices.Collect(ch)
	e.globalBytesTotal.Collect(ch)
	e.uptimeSeconds.Collect(ch)

	e.deviceDownloadBps.Collect(ch)
	e.deviceUploadBps.Collect(ch)
	e.deviceActiveConnections.Collect(ch)
	e.deviceBytesTotal.Collect(ch)
	e.deviceSessionBytes.Collect(ch)

	e.protocolBytesTotal.Collect(ch)
}
