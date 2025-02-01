package monitor

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip monitor ../bpf/monitor.bpf.c

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/olekukonko/tablewriter"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/kisy/probpf/config"
)

// HostKey 映射 C 结构体
type HostKey struct {
	LocalMac   [6]byte
	LocalAddr  [16]byte
	RemoteAddr [16]byte
	LocalPort  uint16
	RemotePort uint16
	Proto      uint8
	IPVer      uint8
}

// HostStats 映射 C 结构体
type HostStats struct {
	RxBytes uint64
	TxBytes uint64
}

// HostDelta 跟踪连接活动
type HostDeltaStats struct {
	RangeRxBytes     uint64    // 两次差值接收字节数
	RangeTxBytes     uint64    // 两次差值发送字节数
	SpeedRxBytes     uint64    // 实时速率接收字节数
	SpeedTxBytes     uint64    // 实时速率发送字节数
	LastTotalRxBytes uint64    // 上次计算统计接收字节数
	LastTotalTxBytes uint64    // 上次计算统计发送字节数
	LastSpeedRxBytes uint64    // 上次计算速率接收字节数
	LastSpeedTxBytes uint64    // 上次计算速率发送字节数
	TotalUpdateTime  time.Time // 上次计算统计时间
}

type Monitor struct {
	xdpLink        link.Link
	tcFilter       netlink.BpfFilter
	stats          *ebpf.Map
	startTime      time.Time
	ifaceName      string
	ifaceIndex     int
	deltaStatsMap  map[HostKey]*HostDeltaStats
	deltaStatsMu   sync.RWMutex
	lastBpfLen     int
	lastUpdateTime time.Time
	lastTotalTime  time.Time
	HostNameMap    map[string]string
	TotalInterval  int
	SyncInterval   int
	CleanInterval  int
}

// 获取协议名称
func getProtoName(proto uint8) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("%d", proto)
	}
}

// 格式化字节数
func formatBytes(bytes uint64) string {
	if bytes >= 1024*1024*1024 {
		return fmt.Sprintf("%.2f GB", float64(bytes)/(1024*1024*1024))
	} else if bytes >= 1024*1024 {
		return fmt.Sprintf("%.2f MB", float64(bytes)/(1024*1024))
	} else if bytes >= 1024 {
		return fmt.Sprintf("%.2f KB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%d B", bytes)
}

// 格式化 IP:Port
func formatIPPort(ip net.IP, port uint16) string {
	return fmt.Sprintf("%s:%d", ip.String(), port)
}

// 格式化 MAC 地址
func formatMAC(mac [6]byte) string {
	return net.HardwareAddr(mac[:]).String()
}

func NewMonitor(cfg config.Config) (*Monitor, error) {
	objs := monitorObjects{}
	if err := loadMonitorObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %v", err)
	}

	ifaceLink, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("getting interface: %v", err)
	}
	ifaceIndex := ifaceLink.Attrs().Index

	// 先创建 XDP link
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpMonitor,
		Interface: ifaceIndex,
		Flags:     config.FormatXDPMode(cfg.XDPMode),
	})
	if err != nil {
		return nil, fmt.Errorf("attaching XDP: %v", err)
	}

	filters, err := netlink.FilterList(ifaceLink, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		xdpLink.Close()
		return nil, fmt.Errorf("list filters failed: %v", err)
	}

	// 删除同名的 filter
	for _, filter := range filters {
		if bpfFilter, ok := filter.(*netlink.BpfFilter); ok {
			if bpfFilter.Name == "tc_monitor" {
				if err := netlink.FilterDel(filter); err != nil {
					xdpLink.Close()
					return nil, fmt.Errorf("delete existing filter failed: %v", err)
				}
			}
		}
	}

	// clsact qdisc 存在
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifaceIndex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	// 尝试添加 qdisc，忽略"已存在"错误
	if err := netlink.QdiscAdd(qdisc); err != nil && !strings.Contains(err.Error(), "file exists") {
		xdpLink.Close()
		return nil, fmt.Errorf("adding qdisc: %v", err)
	}

	// 4. 添加新的 TC filter
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifaceIndex,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           objs.TcMonitor.FD(),
		Name:         "tc_monitor", // 用特定名称标识我们的 filter
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		xdpLink.Close()
		return nil, fmt.Errorf("adding TC filter: %v", err)
	}

	return &Monitor{
		xdpLink:       xdpLink,
		tcFilter:      *filter,
		stats:         objs.HostStats,
		startTime:     time.Now(),
		ifaceName:     cfg.Interface,
		ifaceIndex:    ifaceIndex, // 保存接口索引
		deltaStatsMap: make(map[HostKey]*HostDeltaStats),
		lastBpfLen:    0,

		lastTotalTime: time.Now(),

		HostNameMap:   cfg.Hostname,
		TotalInterval: cfg.TotalInterval,
		SyncInterval:  cfg.SyncInterval,
		CleanInterval: cfg.CleanInterval,
	}, nil
}

// UpdateStats 更新缓存的统计数据
func (m *Monitor) UpdateStats() {
	now := time.Now()

	var key HostKey
	var stats HostStats
	lastBpfLen := 0
	// 获取新数据
	iter := m.stats.Iterate()

	m.deltaStatsMu.Lock()
	m.lastUpdateTime = now

	if now.Sub(m.lastTotalTime) >= time.Duration(m.TotalInterval)*time.Second {
		m.lastTotalTime = now
	}

	for iter.Next(&key, &stats) {
		lastBpfLen++

		deltaStats, deltaExists := m.deltaStatsMap[key]

		if !deltaExists {
			deltaStats = &HostDeltaStats{
				RangeRxBytes:     stats.RxBytes,
				RangeTxBytes:     stats.TxBytes,
				LastTotalRxBytes: stats.RxBytes,
				LastTotalTxBytes: stats.TxBytes,
				TotalUpdateTime:  now,

				SpeedRxBytes:     0,
				SpeedTxBytes:     0,
				LastSpeedRxBytes: stats.RxBytes,
				LastSpeedTxBytes: stats.RxBytes,
			}
			m.deltaStatsMap[key] = deltaStats
		} else {
			deltaStats.SpeedRxBytes = (stats.RxBytes - deltaStats.LastSpeedRxBytes) / uint64(m.SyncInterval)
			deltaStats.SpeedTxBytes = (stats.TxBytes - deltaStats.LastSpeedTxBytes) / uint64(m.SyncInterval)
			deltaStats.LastSpeedRxBytes = stats.RxBytes
			deltaStats.LastSpeedTxBytes = stats.TxBytes
		}

		// 不需要更新统计数据
		if m.lastTotalTime != now {
			continue
		}

		// 更新统计数据
		if stats.RxBytes != deltaStats.LastTotalRxBytes || stats.TxBytes != deltaStats.LastTotalTxBytes {
			deltaStats.RangeRxBytes = stats.RxBytes - deltaStats.LastTotalRxBytes
			deltaStats.RangeTxBytes = stats.TxBytes - deltaStats.LastTotalTxBytes
			deltaStats.LastTotalRxBytes = stats.RxBytes
			deltaStats.LastTotalTxBytes = stats.TxBytes
			deltaStats.TotalUpdateTime = now
		} else if now.Sub(deltaStats.TotalUpdateTime) > time.Duration(m.CleanInterval)*time.Second {
			// 清理过期连接
			delete(m.deltaStatsMap, key)
			m.stats.Delete(&key)
		}
	}

	m.lastBpfLen = lastBpfLen
	m.deltaStatsMu.Unlock()
}

func (m *Monitor) PrintStats() {
	// 使用缓存的数据
	m.deltaStatsMu.RLock()
	latestStats := make(map[HostKey]HostStats, len(m.deltaStatsMap))
	for k, v := range m.deltaStatsMap {
		latestStats[k] = HostStats{
			RxBytes: v.LastSpeedRxBytes,
			TxBytes: v.LastSpeedTxBytes,
		}
	}
	lastBpfLen := m.lastBpfLen
	lastUpdate := m.lastUpdateTime
	m.deltaStatsMu.RUnlock()

	// 清屏并移动光标到开头
	fmt.Printf("\033[2J\033[H")

	// 打印系统信息表格
	infoTable := tablewriter.NewWriter(os.Stdout)
	infoTable.SetHeader([]string{"Information", "Value"})
	infoTable.SetColumnAlignment([]int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT})
	infoTable.SetBorder(true)
	infoTable.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	infoTable.SetRowLine(true)
	infoTable.SetAlignment(tablewriter.ALIGN_LEFT)

	infoTable.Append([]string{"Interface", m.ifaceName})
	infoTable.Append([]string{"Runtime", time.Since(m.startTime).Round(time.Second).String()})
	infoTable.Append([]string{"Connections", fmt.Sprintf("%d:%d", len(latestStats), lastBpfLen)})
	infoTable.Append([]string{"Last Update", lastUpdate.UTC().Format("2006-01-02 15:04:05")})
	infoTable.Render()
	fmt.Println()

	// 创建网络统计数据表格
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Host Name", "Host Address", "Remote Address", "Protocol", "RX", "TX"})
	table.SetBorder(true)
	table.SetColumnAlignment([]int{
		tablewriter.ALIGN_LEFT,   // MAC
		tablewriter.ALIGN_LEFT,   // Local Address
		tablewriter.ALIGN_LEFT,   // Remote Address
		tablewriter.ALIGN_CENTER, // Protocol
		tablewriter.ALIGN_RIGHT,  // RX
		tablewriter.ALIGN_RIGHT,  // TX
	})
	table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderLine(true)
	table.SetBorders(tablewriter.Border{Left: true, Top: true, Right: true, Bottom: true})

	// 遍历缓存的数据
	for key, stats := range latestStats {
		var localIP, remoteIP net.IP
		if key.IPVer == 4 {
			localIP = net.IP(key.LocalAddr[:4])
			remoteIP = net.IP(key.RemoteAddr[:4])
		} else {
			localIP = net.IP(key.LocalAddr[:])
			remoteIP = net.IP(key.RemoteAddr[:])
		}

		mac := formatMAC(key.LocalMac)
		localName, exists := m.HostNameMap[mac]
		if !exists {
			localName = mac
		}

		table.Append([]string{
			localName,
			formatIPPort(localIP, key.LocalPort),
			formatIPPort(remoteIP, key.RemotePort),
			getProtoName(key.Proto),
			formatBytes(stats.RxBytes),
			formatBytes(stats.TxBytes),
		})
	}

	// 渲染表格
	table.Render()
}

func (m *Monitor) Close() {
	if m.xdpLink != nil {
		// 增加错误处理
		if err := m.xdpLink.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error detaching XDP program: %v\n", err)
		}
	}

	if m.tcFilter.Fd != 0 {
		err := netlink.FilterDel(&m.tcFilter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error clean TC filter: %v\n", err)
		}
	}

	link, err := netlink.LinkByIndex(m.tcFilter.LinkIndex)
	if err == nil {
		netlink.QdiscDel(&netlink.GenericQdisc{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Handle:    netlink.MakeHandle(0xffff, 0),
				Parent:    netlink.HANDLE_CLSACT,
			},
			QdiscType: "clsact",
		})
	}
}
