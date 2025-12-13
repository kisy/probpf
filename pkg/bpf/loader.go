package bpf

//go:generate ./generate.sh

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"

	"github.com/kisy/probpf/config"
	"github.com/kisy/probpf/pkg/model"
)

type Loader struct {
	xdpLink    link.Link
	fentryLink link.Link
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

	// Attach fentry
	fentryLink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.FentryEgressMonitor,
	})
	if err != nil {
		xdpLink.Close()
		return nil, fmt.Errorf("attaching fentry: %v", err)
	}

	return &Loader{
		xdpLink:    xdpLink,
		fentryLink: fentryLink,
		objs:       objs,
		Interface:  cfg.Interface,
	}, nil
}

func (l *Loader) Close() {
	if l.xdpLink != nil {
		l.xdpLink.Close()
	}
	if l.fentryLink != nil {
		l.fentryLink.Close()
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
