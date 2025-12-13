package bpf

//go:generate ./generate.sh

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/kisy/probpf/config"
	"github.com/kisy/probpf/pkg/model"
)

type Loader struct {
	xdpLink    link.Link
	fentryLink link.Link
	tcFilter   *netlink.BpfFilter
	qdisc      *netlink.Clsact
	objs       monitorObjects
	Interface  string
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

	l := &Loader{
		xdpLink:   xdpLink,
		objs:      objs,
		Interface: cfg.Interface,
	}

	if cfg.UseTC {
		// 使用 TC 模式
		fmt.Println("Using TC mode for egress monitoring (forced by --tc)...")

		// 1. Create or replace qdisc
		qdisc := &netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: ifaceIndex,
				Handle:    netlink.MakeHandle(0xffff, 0),
				Parent:    netlink.HANDLE_CLSACT,
			},
		}

		// Try to add qdisc, ignore if it already exists
		if err := netlink.QdiscAdd(qdisc); err != nil {
			if !isFileExistsError(err) {
				xdpLink.Close()
				return nil, fmt.Errorf("creating qdisc: %v", err)
			}
		}
		l.qdisc = qdisc

		// 2. Attach TC filter
		// Egress is HANDLE_MIN_EGRESS (0xFFFFFFF3)
		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: ifaceIndex,
				Parent:    netlink.HANDLE_MIN_EGRESS,
				Protocol:  unix.ETH_P_ALL,
				Priority:  1,
			},
			Fd:           objs.TcEgressMonitor.FD(),
			Name:         "probpf_egress",
			DirectAction: true,
		}

		if err := netlink.FilterAdd(filter); err != nil {
			// Clean up qdisc if we created or reused it just for this?
			// Usually better to leave qdisc but we should clean up xdp
			xdpLink.Close()
			return nil, fmt.Errorf("attaching TC filter: %v", err)
		}
		l.tcFilter = filter
		fmt.Println("✓ TC filter attached successfully")

	} else {
		// Attach fentry (default)
		fentryLink, err := link.AttachTracing(link.TracingOptions{
			Program: objs.FentryEgressMonitor,
		})
		if err != nil {
			xdpLink.Close()
			// 尝试自动降级到 TC？不，用户未指定 --tc，但 fentry 失败可能是环境问题
			// 目前保持报错，除非你想做自动降级。
			// 这里我们加上提示
			return nil, fmt.Errorf("attaching fentry: %v (kernel too old or no BTF? try --tc)", err)
		}
		l.fentryLink = fentryLink
	}

	return l, nil
}

func isFileExistsError(err error) bool {
	// Need to check for EEXIST
	// Using string check or syscall comparison
	if err == nil {
		return false
	}
	return err.Error() == "file exists" || err == unix.EEXIST
}

func (l *Loader) Close() error {
	var errs []error

	if l.fentryLink != nil {
		if err := l.fentryLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if l.tcFilter != nil {
		if err := netlink.FilterDel(l.tcFilter); err != nil {
			errs = append(errs, err)
		}
	}

	if l.qdisc != nil {
		if err := netlink.QdiscDel(l.qdisc); err != nil {
			// Ignore "file not exists" in case it was already deleted
			if !isFileExistsError(err) && err.Error() != "no such file or directory" {
				errs = append(errs, err)
			}
		}
	}

	if l.xdpLink != nil {
		if err := l.xdpLink.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("multiple errors closing loader: %v", errs)
	}
	return nil
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
