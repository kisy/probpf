package monitor

import (
	"fmt"
	"net"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

type PrometheusCollector struct {
	monitor     *Monitor
	rangeRxDesc *prometheus.Desc
	rangeTxDesc *prometheus.Desc
	speedRxDesc *prometheus.Desc
	speedTxDesc *prometheus.Desc
}

func NewPrometheusCollector(m *Monitor) *PrometheusCollector {
	return &PrometheusCollector{
		monitor: m,
		rangeRxDesc: prometheus.NewDesc(
			"probpf_rx_bytes",
			"Number of bytes received since last scrape",
			[]string{"host", "ip", "port", "remote_ip", "remote_port", "proto", "timestamp"},
			nil,
		),
		rangeTxDesc: prometheus.NewDesc(
			"probpf_tx_bytes",
			"Number of bytes transmitted since last scrape",
			[]string{"host", "ip", "port", "remote_ip", "remote_port", "proto", "timestamp"},
			nil,
		),
		speedRxDesc: prometheus.NewDesc(
			"probpf_rx_speed",
			"Number of bytes received per second",
			[]string{"host", "ip", "port", "remote_ip", "remote_port", "proto"},
			nil,
		),
		speedTxDesc: prometheus.NewDesc(
			"probpf_tx_speed",
			"Number of bytes transmitted per second",
			[]string{"host", "ip", "port", "remote_ip", "remote_port", "proto"},
			nil,
		),
	}
}

func (c *PrometheusCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.rangeRxDesc
	ch <- c.rangeTxDesc
	ch <- c.speedRxDesc
	ch <- c.speedTxDesc
}

func (c *PrometheusCollector) Collect(ch chan<- prometheus.Metric) {
	// 从 monitor 获取当前缓存的数据
	c.monitor.deltaStatsMu.RLock()
	currentStats := make(map[HostKey]*HostDeltaStats, len(c.monitor.deltaStatsMap))
	for k, v := range c.monitor.deltaStatsMap {
		currentStats[k] = &HostDeltaStats{
			RangeRxBytes:    v.RangeRxBytes,
			RangeTxBytes:    v.RangeTxBytes,
			SpeedRxBytes:    v.SpeedRxBytes,
			SpeedTxBytes:    v.SpeedTxBytes,
			TotalUpdateTime: v.TotalUpdateTime,
		}
	}
	timestamp := c.monitor.lastTotalTime.Unix()
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

		localName := c.monitor.GetHostName(key.LocalMac)

		labels := []string{
			localName,
			localIP,
			fmt.Sprint(key.LocalPort),
			remoteIP,
			fmt.Sprint(key.RemotePort),
			getProtoName(key.Proto),
			fmt.Sprint(timestamp),
		}

		// 输出时间区间统计
		if stats.RangeRxBytes > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.rangeRxDesc,
				prometheus.GaugeValue,
				float64(stats.RangeRxBytes),
				labels...,
			)
		}
		if stats.RangeTxBytes > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.rangeTxDesc,
				prometheus.GaugeValue,
				float64(stats.RangeTxBytes),
				labels...,
			)
		}

		// 计算速度
		ch <- prometheus.MustNewConstMetric(
			c.speedRxDesc,
			prometheus.GaugeValue,
			float64(stats.SpeedRxBytes),
			labels[:len(labels)-1]...,
		)
		ch <- prometheus.MustNewConstMetric(
			c.speedTxDesc,
			prometheus.GaugeValue,
			float64(stats.SpeedTxBytes),
			labels[:len(labels)-1]...,
		)
	}
}

func init() {
	// 取消注册默认的 Go metrics
	prometheus.Unregister(collectors.NewGoCollector())
	prometheus.Unregister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}
