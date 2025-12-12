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
	globalBytesTotal        *prometheus.CounterVec
	uptimeSeconds           prometheus.Gauge

	// Track previous values for delta calculation
	lastGlobalDownload uint64
	lastGlobalUpload   uint64
	lastDeviceBytes    map[string]map[string]uint64 // mac -> direction -> bytes

	// Device-level metrics
	deviceDownloadBps       *prometheus.GaugeVec
	deviceUploadBps         *prometheus.GaugeVec
	deviceActiveConnections *prometheus.GaugeVec
	deviceBytesTotal        *prometheus.CounterVec
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
			Help: "Global download speed in bytes per second",
		}),
		globalUploadBps: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probpf_global_upload_bps",
			Help: "Global upload speed in bytes per second",
		}),
		globalActiveConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probpf_global_active_connections",
			Help: "Total number of active connections",
		}),
		globalActiveDevices: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probpf_global_active_devices",
			Help: "Number of active devices",
		}),
		globalBytesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "probpf_global_bytes_total",
				Help: "Total bytes transferred globally (counter, survives restarts)",
			},
			[]string{"direction"}, // "download" or "upload"
		),
		uptimeSeconds: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probpf_uptime_seconds",
			Help: "ProBPF uptime in seconds",
		}),

		// Initialize delta tracking
		lastGlobalDownload: 0,
		lastGlobalUpload:   0,
		lastDeviceBytes:    make(map[string]map[string]uint64),

		// Device-level metrics
		deviceDownloadBps: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "probpf_device_download_bps",
				Help: "Device download speed in bytes per second",
			},
			[]string{"mac", "name"},
		),
		deviceUploadBps: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "probpf_device_upload_bps",
				Help: "Device upload speed in bytes per second",
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
		deviceBytesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "probpf_device_bytes_total",
				Help: "Total bytes transferred by device (counter, survives restarts)",
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
	e.globalDownloadBps.Set(float64(globalStats.DownloadSpeed))
	e.globalUploadBps.Set(float64(globalStats.UploadSpeed))
	e.globalActiveConnections.Set(float64(globalStats.ActiveConnections))

	// Calculate and add deltas for global bytes (Counter)
	if globalStats.TotalDownload > e.lastGlobalDownload {
		delta := globalStats.TotalDownload - e.lastGlobalDownload
		e.globalBytesTotal.WithLabelValues("download").Add(float64(delta))
		e.lastGlobalDownload = globalStats.TotalDownload
	}
	if globalStats.TotalUpload > e.lastGlobalUpload {
		delta := globalStats.TotalUpload - e.lastGlobalUpload
		e.globalBytesTotal.WithLabelValues("upload").Add(float64(delta))
		e.lastGlobalUpload = globalStats.TotalUpload
	}

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
		e.deviceDownloadBps.WithLabelValues(mac, name).Set(float64(client.DownloadSpeed))
		e.deviceUploadBps.WithLabelValues(mac, name).Set(float64(client.UploadSpeed))
		e.deviceActiveConnections.WithLabelValues(mac, name).Set(float64(client.ActiveConnections))

		// Calculate and add deltas for device bytes (Counter)
		if e.lastDeviceBytes[mac] == nil {
			e.lastDeviceBytes[mac] = make(map[string]uint64)
		}

		// Download
		lastDownload := e.lastDeviceBytes[mac]["download"]
		if client.TotalDownload > lastDownload {
			delta := client.TotalDownload - lastDownload
			e.deviceBytesTotal.WithLabelValues(mac, name, "download").Add(float64(delta))
			e.lastDeviceBytes[mac]["download"] = client.TotalDownload
		}

		// Upload
		lastUpload := e.lastDeviceBytes[mac]["upload"]
		if client.TotalUpload > lastUpload {
			delta := client.TotalUpload - lastUpload
			e.deviceBytesTotal.WithLabelValues(mac, name, "upload").Add(float64(delta))
			e.lastDeviceBytes[mac]["upload"] = client.TotalUpload
		}

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
