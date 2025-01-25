package monitor

import (
	"fmt"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

type CachedDelta struct {
	RxDelta  uint64
	TxDelta  uint64
	LastSeen time.Time
}

type PrometheusCollector struct {
	monitor *Monitor
	rxDesc  *prometheus.Desc
	txDesc  *prometheus.Desc
}

func NewPrometheusCollector(m *Monitor) *PrometheusCollector {
	return &PrometheusCollector{
		monitor: m,
		rxDesc: prometheus.NewDesc(
			"probpf_rx_bytes",
			"Number of bytes received since last scrape",
			[]string{"mac", "ip", "port", "remote_ip", "remote_port", "proto", "timestamp"},
			nil,
		),
		txDesc: prometheus.NewDesc(
			"probpf_tx_bytes",
			"Number of bytes transmitted since last scrape",
			[]string{"mac", "ip", "port", "remote_ip", "remote_port", "proto", "timestamp"},
			nil,
		),
	}
}

func (c *PrometheusCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.rxDesc
	ch <- c.txDesc
}

func (c *PrometheusCollector) Collect(ch chan<- prometheus.Metric) {
	// 从 monitor 获取当前缓存的数据
	c.monitor.deltaStatsMu.RLock()
	currentStats := make(map[HostKey]HostStats, len(c.monitor.deltaStatsMap))
	for k, v := range c.monitor.deltaStatsMap {
		currentStats[k] = HostStats{
			RxBytes: v.RangeRxBytes,
			TxBytes: v.RangeTxBytes,
		}
	}
	timestamp := c.monitor.lastUpdateTime.Unix()
	c.monitor.deltaStatsMu.RUnlock()

	for key, stats := range currentStats {
		// 准备标签
		var localIP, remoteIP string
		if key.IPVer == 4 {
			localIP = net.IP(key.LocalAddr[:4]).String()
			remoteIP = net.IP(key.RemoteAddr[:4]).String()
		} else {
			localIP = net.IP(key.LocalAddr[:]).String()
			remoteIP = net.IP(key.RemoteAddr[:]).String()
		}

		labels := []string{
			formatMAC(key.LocalMac),
			localIP,
			fmt.Sprint(key.LocalPort),
			remoteIP,
			fmt.Sprint(key.RemotePort),
			getProtoName(key.Proto),
			fmt.Sprint(timestamp),
		}

		// 输出差值
		if stats.RxBytes > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.rxDesc,
				prometheus.GaugeValue,
				float64(stats.RxBytes),
				labels...,
			)
		}
		if stats.TxBytes > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.txDesc,
				prometheus.GaugeValue,
				float64(stats.TxBytes),
				labels...,
			)
		}
	}
}

func init() {
	// 取消注册默认的 Go metrics
	prometheus.Unregister(collectors.NewGoCollector())
	prometheus.Unregister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}
