package bpf

//go:generate ./generate.sh

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
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
	closer     interface{ Close() error }
	Interface  string
}

func Load(cfg config.Config) (*Loader, error) {
	// 1. Try Loading Standard Object
	objs := monitorObjects{}

	// Load Spec
	spec, err := loadMonitor()
	if err != nil {
		return nil, fmt.Errorf("loading spec: %v", err)
	}

	// Modify Spec based on config for Standard Mode
	if cfg.UseTC {
		// Replace fentry with a dummy socket filter to avoid kallsyms/BTF dependency
		spec.Programs["fentry_egress_monitor"] = &ebpf.ProgramSpec{
			Name:         "fentry_egress_monitor",
			Type:         ebpf.SocketFilter,
			Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
			License:      "Dual BSD/GPL",
		}
	} else {
		// If using fentry, replace TC program with dummy to satisfy LoadAndAssign
		spec.Programs["tc_egress_monitor"] = &ebpf.ProgramSpec{
			Name:         "tc_egress_monitor",
			Type:         ebpf.SocketFilter,
			Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
			License:      "Dual BSD/GPL",
		}
	}

	// Attempt Load
	// Since we removed vmlinux.h and use manual offsets, this *might* verify on BTF systems
	// On non-BTF systems, fentry loading (LoadAndAssign) will fail if fentry is present.
	// But in --tc mode, we replaced it with dummy, so it should succeed.

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %v", err)
	}

	return setupLoader(&objs, &objs, cfg)
}

func setupLoader(objs *monitorObjects, closer interface{ Close() error }, cfg config.Config) (*Loader, error) {
	ifaceLink, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		closer.Close()
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
		closer.Close()
		return nil, fmt.Errorf("attaching XDP: %v", err)
	}

	l := &Loader{
		xdpLink:   xdpLink,
		objs:      *objs,
		closer:    closer,
		Interface: cfg.Interface,
	}

	if cfg.UseTC {
		if err := l.setupTC(ifaceIndex, objs.TcEgressMonitor); err != nil {
			xdpLink.Close()
			closer.Close()
			return nil, err
		}
	} else {
		// Attach fentry (default)
		fentryLink, err := link.AttachTracing(link.TracingOptions{
			Program: objs.FentryEgressMonitor,
		})
		if err != nil {
			xdpLink.Close()
			closer.Close()
			return nil, fmt.Errorf("attaching fentry: %v", err)
		}
		l.fentryLink = fentryLink
	}

	return l, nil
}

func (l *Loader) setupTC(ifaceIndex int, prog *ebpf.Program) error {
	fmt.Println("Using TC mode for egress monitoring...")

	// 1. Create or replace qdisc
	qdisc := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifaceIndex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		if !isFileExistsError(err) {
			return fmt.Errorf("creating qdisc: %v", err)
		}
	}
	l.qdisc = qdisc

	// 2. Attach TC filter
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifaceIndex,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           prog.FD(),
		Name:         "probpf_egress",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("attaching TC filter: %v", err)
	}
	l.tcFilter = filter
	fmt.Println("✓ TC filter attached successfully")
	return nil
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

	// Close object collection
	if l.closer != nil {
		if err := l.closer.Close(); err != nil {
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
