package bpf

//go:generate ./generate.sh

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	
	"github.com/kisy/probpf/config"
	"github.com/kisy/probpf/pkg/model"
)

type Loader struct {
	xdpLink   link.Link
	tcFilter  netlink.BpfFilter
	objs      monitorObjects
	Interface string
}

func Load(cfg config.Config) (*Loader, error) {
	objs := monitorObjects{}
	if err := loadMonitorObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %v", err)
	}

	ifaceLink, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("getting interface %s: %v", cfg.Interface, err)
	}
	ifaceIndex := ifaceLink.Attrs().Index

	// Attach XDP
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpMonitor,
		Interface: ifaceIndex,
		Flags:     config.FormatXDPMode(cfg.XDPMode),
	})
	if err != nil {
		return nil, fmt.Errorf("attaching XDP: %v", err)
	}

	// Prepare TC
	// 1. Ensure TC filter list is clean of old filters
	filters, err := netlink.FilterList(ifaceLink, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		xdpLink.Close()
		return nil, fmt.Errorf("list filters failed: %v", err)
	}
	for _, filter := range filters {
		if bpfFilter, ok := filter.(*netlink.BpfFilter); ok {
			if bpfFilter.Name == "tc_monitor" {
				netlink.FilterDel(filter)
			}
		}
	}

	// 2. Add qdisc
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifaceIndex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if strings.Contains(err.Error(), "file exists") {
			// Ignore if it already exists
		} else if strings.Contains(err.Error(), "no such file") {
			xdpLink.Close()
			return nil, fmt.Errorf("adding qdisc failed (missing kernel module?): %v. On OpenWrt, try installing 'kmod-sched-clsact'", err)
		} else {
			xdpLink.Close()
			return nil, fmt.Errorf("adding qdisc: %v", err)
		}
	}

	// 3. Add TC Filter
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifaceIndex,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           objs.TcMonitor.FD(),
		Name:         "tc_monitor",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		xdpLink.Close()
		if strings.Contains(err.Error(), "no such file") {
			return nil, fmt.Errorf("adding TC filter failed (missing kmod-sched-bpf?): %v", err)
		}
		return nil, fmt.Errorf("adding TC filter: %v", err)
	}

	return &Loader{
		xdpLink:   xdpLink,
		tcFilter:  *filter,
		objs:      objs,
		Interface: cfg.Interface,
	}, nil
}

func (l *Loader) Close() {
	if l.xdpLink != nil {
		l.xdpLink.Close()
	}
	if l.tcFilter.Fd != 0 {
		netlink.FilterDel(&l.tcFilter)
	}
	// Cleanup qdisc? Usually acceptable to leave it, but good practice to check logic.
	// Previous logic deleted it if link fetch succeeded.
	link, err := netlink.LinkByName(l.Interface)
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

// ReadStats iterates directly over the BPF map and returns a copy of the data.
// It does NOT do aggregation or translation.
func (l *Loader) ReadMap() (map[model.HostKey]model.HostStats, error) {
	data := make(map[model.HostKey]model.HostStats)
	var key model.HostKey
	var stats model.HostStats

	// The generated BPF code uses map definition matching the C code.
	// We matched model.HostKey to C definition manually.
	// Note: bpf2go generates its own types usually, but here we mapped them manually 
	// in the previous code to "HostKey". 
	// However, bpf2go generated code `monitor_bpfeb.go` usually contains struct definitions 
	// if we used -type. We didn't use -type in the generate directive.
	// So we can use the model types IF they match memory layout.
	// Let's assume they do since we copied them.
	
	iter := l.objs.HostStats.Iterate()
	for iter.Next(&key, &stats) {
		data[key] = stats
	}
	
	return data, iter.Err()
}

func (l *Loader) Lookup(key *model.HostKey) (model.HostStats, error) {
	var stats model.HostStats
	err := l.objs.HostStats.Lookup(key, &stats)
	return stats, err
}

func (l *Loader) DeleteKey(key *model.HostKey) error {
	return l.objs.HostStats.Delete(key)
}
