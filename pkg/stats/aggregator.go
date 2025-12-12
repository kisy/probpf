package stats

import (
	"net"
	"sort"
	"sync"
	"time"

	"github.com/kisy/probpf/pkg/bpf"
	"github.com/kisy/probpf/pkg/model"
)

func formatIP(addr [16]byte, ver uint8) string {
	if ver == 4 {
		return net.IP(addr[:4]).String()
	}
	return net.IP(addr[:]).String()
}

func formatMAC(mac [6]byte) string {
	return net.HardwareAddr(mac[:]).String()
}

type Aggregator struct {
	loader      *bpf.Loader
	hostnameMap map[string]string

	mu         sync.RWMutex
	startTime  time.Time
	lastUpdate time.Time

	// Configuration
	gcInterval time.Duration
	dataTTL    time.Duration

	detailCacheDuration time.Duration
	nextGC              time.Time

	// Data Stores
	history    map[string]model.HostStats        // Accumulated bytes from closed flows (MAC key)
	flowCache  map[model.HostKey]model.HostStats // Last known value of every flow
	prevTotals map[string]model.HostStats        // Previous Display Total (for speed calc) (MAC key)
	display    map[string]*model.ClientStats     // Current Display State (MAC key)

	// LAN Filtering
	ignoreLocal bool
	localCIDRs  []*net.IPNet

	// New State Tracking
	clientStartTimes map[string]time.Time
	clientLastActive map[string]time.Time
	prevFlowCache    map[model.HostKey]model.HostStats // For per-flow speed calc
	flowSpeeds       map[model.HostKey]model.HostStats // RxBytes/TxBytes here mean Speed
	flowStartTimes   map[model.HostKey]time.Time       // Track start time of each flow

	globalStats model.GlobalStats

	// Clean Tracking
	keyLastSeen map[model.HostKey]time.Time

	// Detail Caching
	clientWatchList map[string]time.Time

	// Session Baselines
	flowBaselines   map[model.HostKey]model.HostStats
	clientBaselines map[string]model.ClientStats
}

func NewAggregator(loader *bpf.Loader, hostnameMap map[string]string) *Aggregator {
	return &Aggregator{
		loader:              loader,
		hostnameMap:         hostnameMap,
		startTime:           time.Now(),
		lastUpdate:          time.Now(),
		clientWatchList:     make(map[string]time.Time),
		history:             make(map[string]model.HostStats),
		flowCache:           make(map[model.HostKey]model.HostStats),
		prevTotals:          make(map[string]model.HostStats),
		display:             make(map[string]*model.ClientStats),
		keyLastSeen:         make(map[model.HostKey]time.Time),
		clientStartTimes:    make(map[string]time.Time),
		clientLastActive:    make(map[string]time.Time),
		prevFlowCache:       make(map[model.HostKey]model.HostStats),
		flowBaselines:       make(map[model.HostKey]model.HostStats),
		clientBaselines:     make(map[string]model.ClientStats),
		flowSpeeds:          make(map[model.HostKey]model.HostStats),
		flowStartTimes:      make(map[model.HostKey]time.Time),
		gcInterval:          60 * time.Second,
		dataTTL:             300 * time.Second,
		detailCacheDuration: 2 * time.Minute,
		nextGC:              time.Now().Add(60 * time.Second),
	}
}

func (a *Aggregator) SetConfig(gcInterval, dataTTL time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gcInterval = gcInterval
	a.dataTTL = dataTTL
	a.nextGC = time.Now().Add(gcInterval)
}

func (a *Aggregator) SetDetailCacheDuration(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.detailCacheDuration = d
}

func (a *Aggregator) SetLocalFiltering(ignore bool, cidrs []*net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ignoreLocal = ignore
	a.localCIDRs = cidrs
}

func (a *Aggregator) isIgnoredKey(k model.HostKey) bool {
	// 1. Basic Multicast/Broadcast Check
	check := func(addr [16]byte, ver uint8) bool {
		var ip net.IP
		if ver == 4 {
			ip = net.IP(addr[:4])
			// IPv4 Explicit Broadcast or Subnet Broadcast (heuristic .255)
			if ip.Equal(net.IPv4bcast) {
				return true
			}
			if ip[3] == 255 {
				return true
			}
		} else {
			ip = net.IP(addr[:])
		}
		return ip.IsMulticast()
	}
	if check(k.ClientIP, k.IPVer) || check(k.RemoteIP, k.IPVer) {
		return true
	}

	// 2. Local Traffic Check
	// Only if filtering is enabled and we have CIDRs
	// Safe to read without lock IF this is called only from Update() which holds main lock?
	// Update() holds a.mu.Lock(), so yes it's safe to access a.ignoreLocal and a.localCIDRs.
	if a.ignoreLocal && len(a.localCIDRs) > 0 {
		var clientIP, remoteIP net.IP
		if k.IPVer == 4 {
			clientIP = net.IP(k.ClientIP[:4])
			remoteIP = net.IP(k.RemoteIP[:4])
		} else {
			clientIP = net.IP(k.ClientIP[:])
			remoteIP = net.IP(k.RemoteIP[:])
		}

		clientIsLocal := false
		for _, network := range a.localCIDRs {
			if network.Contains(clientIP) {
				clientIsLocal = true
				break
			}
		}

		remoteIsLocal := false
		for _, network := range a.localCIDRs {
			if network.Contains(remoteIP) {
				remoteIsLocal = true
				break
			}
		}

		// If BOTH are local, ignore the traffic
		if clientIsLocal && remoteIsLocal {
			return true
		}
	}

	return false
}

func (a *Aggregator) Update() error {
	rawMap, err := a.loader.ReadMap()
	if err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	dt := now.Sub(a.lastUpdate).Seconds()
	if dt < 0.1 {
		dt = 0.1
	}

	// 1. Process Raw Flows & Track Activity
	activeTotals := make(map[string]model.HostStats)
	activeConns := make(map[string]uint64)

	// Reset Global Stats Accumulators
	var globalRx, globalTx uint64
	var globalSpeedRx, globalSpeedTx uint64

	if a.keyLastSeen == nil {
		a.keyLastSeen = make(map[model.HostKey]time.Time)
	}

	// Helper for speed
	calcSpeed := func(curr, prev uint64) uint64 {
		if curr > prev {
			return uint64(float64(curr-prev) / dt)
		}
		return 0
	}

	for key, currentVal := range rawMap {
		// Filter Multicast/Broadcast
		if a.isIgnoredKey(key) {
			continue
		}

		mac := formatMAC(key.ClientMac)

		// Accumulate Active Totals
		t := activeTotals[mac]
		t.RxBytes += currentVal.RxBytes
		t.TxBytes += currentVal.TxBytes
		activeTotals[mac] = t

		activeConns[mac]++

		// Activity Tracking (for TTL)
		prevVal := a.flowCache[key]

		isActive := false
		if currentVal.RxBytes > prevVal.RxBytes || currentVal.TxBytes > prevVal.TxBytes {
			a.keyLastSeen[key] = now
			isActive = true
		} else {
			if _, exists := a.flowCache[key]; !exists {
				a.keyLastSeen[key] = now
				isActive = true
			}
		}

		// Init Flow Start Time if new to aggregation
		if _, ok := a.flowStartTimes[key]; !ok {
			a.flowStartTimes[key] = now
		}

		if isActive {
			a.clientLastActive[mac] = now

			// Init Start Time if new
			if _, ok := a.clientStartTimes[mac]; !ok {
				a.clientStartTimes[mac] = now
			}
		}

		// Update Cache
		a.flowCache[key] = currentVal
	}

	// 1.5 Calculate Per-Flow Speeds (Before updating cache)
	for key, curr := range a.flowCache {
		mac := formatMAC(key.ClientMac)
		lastReq, watched := a.clientWatchList[mac]
		isWatched := watched && time.Since(lastReq) < a.detailCacheDuration

		if !isWatched {
			delete(a.prevFlowCache, key)
			delete(a.flowBaselines, key)
			delete(a.clientBaselines, mac)
			delete(a.flowSpeeds, key)
			continue
		}

		prev, ok := a.prevFlowCache[key]
		if !ok {
			a.flowSpeeds[key] = model.HostStats{
				RxBytes: uint64(float64(curr.RxBytes) / dt),
				TxBytes: uint64(float64(curr.TxBytes) / dt),
			}
		} else {
			rxSpeed := uint64(0)
			if curr.RxBytes > prev.RxBytes {
				rxSpeed = uint64(float64(curr.RxBytes-prev.RxBytes) / dt)
			}
			txSpeed := uint64(0)
			if curr.TxBytes > prev.TxBytes {
				txSpeed = uint64(float64(curr.TxBytes-prev.TxBytes) / dt)
			}
			a.flowSpeeds[key] = model.HostStats{RxBytes: rxSpeed, TxBytes: txSpeed}
		}
	}

	// 2. Garbage Collection (Inline)
	if now.After(a.nextGC) {
		// A. Clean Stale BPF Keys
		for key, lastSeen := range a.keyLastSeen {
			if now.Sub(lastSeen) > a.dataTTL {
				val := a.flowCache[key]

				mac := formatMAC(key.ClientMac)
				hist := a.history[mac]
				hist.RxBytes += val.RxBytes
				hist.TxBytes += val.TxBytes
				a.history[mac] = hist

				// Delete from BPF
				a.loader.DeleteKey(&key)

				// Cleanup internal
				delete(a.keyLastSeen, key)
				delete(a.flowCache, key)
				delete(a.prevFlowCache, key)
				delete(a.flowBaselines, key)
				delete(a.flowSpeeds, key)
				delete(a.flowStartTimes, key)
			}
		}
		a.nextGC = now.Add(a.gcInterval)
	}

	// 3. Compute Display Stats (History + Active)
	allClients := make(map[string]bool)
	for k := range a.history {
		allClients[k] = true
	}
	for k := range activeTotals {
		allClients[k] = true
	}

	for mac := range allClients {
		hist := a.history[mac]
		act := activeTotals[mac]
		actConns := activeConns[mac] // Helper var

		totalRx := hist.RxBytes + act.RxBytes
		totalTx := hist.TxBytes + act.TxBytes

		// Calculate Speed
		prev := a.prevTotals[mac]
		speedRx := calcSpeed(totalRx, prev.RxBytes)
		speedTx := calcSpeed(totalTx, prev.TxBytes)

		// Smoothing (EMA) - skipping complex EMA for now, direct is fine
		stat, exists := a.display[mac]
		if !exists {
			stat = &model.ClientStats{
				MAC:  mac,
				Name: a.getHostName(mac),
			}
			a.display[mac] = stat
		}

		stat.TotalUpload = totalRx
		stat.TotalDownload = totalTx
		stat.UploadSpeed = speedRx
		stat.DownloadSpeed = speedTx
		stat.ActiveConnections = actConns
		stat.LastUpdate = now
		stat.StartTime = a.clientStartTimes[mac]
		stat.LastActive = a.clientLastActive[mac]
		if stat.StartTime.IsZero() {
			stat.StartTime = a.startTime
		}

		a.prevTotals[mac] = model.HostStats{RxBytes: totalRx, TxBytes: totalTx}

		// Accumulate Global
		globalRx += totalRx
		globalTx += totalTx
		globalSpeedRx += speedRx
		globalSpeedTx += speedTx
		// NOTE: This assumes disjoint sets of active connections.
		// Since we aggregate by MAC, and MACs are unique, sum of active flows per MAC = total active flows.
		// Wait, activeConns counts flows. Yes.
	}

	// Sum global active connections separately to be safe/clear
	var globalActive uint64
	for _, c := range activeConns {
		globalActive += c
	}

	// Update Global Stats
	a.globalStats = model.GlobalStats{
		TotalDownload:     globalTx, // Router TX
		TotalUpload:       globalRx, // Router RX
		DownloadSpeed:     globalSpeedTx,
		UploadSpeed:       globalSpeedRx,
		ActiveConnections: globalActive,
	}

	// Update Prev Flow Cache for next iteration's per-flow speed
	for k, v := range a.flowCache {
		mac := formatMAC(k.ClientMac)
		if lastReq, ok := a.clientWatchList[mac]; ok && now.Sub(lastReq) < a.detailCacheDuration {
			a.prevFlowCache[k] = v
		}
	}

	a.lastUpdate = now
	return nil
}

func (a *Aggregator) Reset() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	for key := range a.keyLastSeen {
		a.loader.DeleteKey(&key)
	}

	a.history = make(map[string]model.HostStats)
	a.flowCache = make(map[model.HostKey]model.HostStats)
	a.prevTotals = make(map[string]model.HostStats)
	a.display = make(map[string]*model.ClientStats)
	a.keyLastSeen = make(map[model.HostKey]time.Time)
	a.clientStartTimes = make(map[string]time.Time)
	a.clientLastActive = make(map[string]time.Time)
	a.clientWatchList = make(map[string]time.Time)
	a.prevFlowCache = make(map[model.HostKey]model.HostStats)
	a.flowBaselines = make(map[model.HostKey]model.HostStats) // Baseline for session-based stats
	a.clientBaselines = make(map[string]model.ClientStats)
	a.flowSpeeds = make(map[model.HostKey]model.HostStats)
	a.flowStartTimes = make(map[model.HostKey]time.Time)
	a.startTime = time.Now()

	return nil
}

func (a *Aggregator) ResetClientByMAC(macStr string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// 1. Identify Client Key and Keys to Delete
	var keysToDelete []model.HostKey
	now := time.Now()

	// Iterate through known keys to find matches
	for k := range a.flowCache {
		if formatMAC(k.ClientMac) == macStr {
			keysToDelete = append(keysToDelete, k)
		}
	}

	// 2. Delete BPF Keys
	for _, k := range keysToDelete {
		a.loader.DeleteKey(&k)
		delete(a.flowCache, k)
		delete(a.prevFlowCache, k)
		delete(a.flowSpeeds, k)
		delete(a.flowStartTimes, k)
		delete(a.keyLastSeen, k)
		delete(a.flowBaselines, k) // FIX: Clear flow baseline on global reset
	}

	delete(a.clientWatchList, macStr)
	delete(a.clientBaselines, macStr) // FIX: Clear client baseline on global reset

	// 3. Clear Internal Stats
	delete(a.history, macStr)
	delete(a.prevTotals, macStr)

	if stat, ok := a.display[macStr]; ok {
		stat.TotalDownload = 0
		stat.TotalUpload = 0
		stat.DownloadSpeed = 0
		stat.UploadSpeed = 0
		stat.ActiveConnections = 0
		stat.StartTime = now
	}
	a.clientStartTimes[macStr] = now
	a.clientLastActive[macStr] = now

	return nil
}

func (a *Aggregator) ResetSessionByMAC(macStr string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()

	// 1. Snapshot Client Baseline
	if s, ok := a.display[macStr]; ok {
		// Snapshot current Total as the new Baseline
		a.clientBaselines[macStr] = *s
		// Reset Session Start Time
		a.clientStartTimes[macStr] = now
	}

	// 2. Snapshot Flow Baselines
	for k, v := range a.flowCache {
		if formatMAC(k.ClientMac) == macStr {
			a.flowBaselines[k] = v
			// We do NOT reset flowStartTimes, because the flow *started* when it started.
			// But Session Duration should be capped by Session Start.
		}
	}

	return nil
}

func (a *Aggregator) GetFlowsByMAC(macStr string) []model.FlowDetail {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Update Watch Timestamp
	a.clientWatchList[macStr] = time.Now()

	// Use a map to aggregate connections (5-tuple) into flows (4-tuple: proto, local, remote, port)
	// Key: string representation of 4-tuple to handle grouping
	type flowKey struct {
		Protocol   string
		LocalIP    string
		RemoteIP   string
		RemotePort uint16
	}

	flowMap := make(map[flowKey]*model.FlowDetail)

	for k, v := range a.flowCache {
		// Match by MAC
		if formatMAC(k.ClientMac) != macStr {
			continue
		}

		speed := a.flowSpeeds[k]

		protocol := protoName(k.Proto)

		// Baseline Logic: Initialize if not present
		baseline, ok := a.flowBaselines[k]
		if !ok {
			// If Flow started AFTER the Client Session Reset, it belongs entirely to this session.
			// So baseline should be 0 (start from scratch).
			// If Flow existed BEFORE, baseline is current value (snapshot at session start).
			flowStart := a.flowStartTimes[k]
			clientStart := a.clientStartTimes[macStr]

			if flowStart.After(clientStart) || flowStart.Equal(clientStart) {
				baseline = model.HostStats{}
			} else {
				baseline = v
			}
			a.flowBaselines[k] = baseline
		}

		// Calculate Session Totals
		sessionTx := uint64(0)
		if v.TxBytes > baseline.TxBytes {
			sessionTx = v.TxBytes - baseline.TxBytes
		}
		sessionRx := uint64(0)
		if v.RxBytes > baseline.RxBytes {
			sessionRx = v.RxBytes - baseline.RxBytes
		}

		localIP := formatIP(k.ClientIP, k.IPVer)
		remoteIP := formatIP(k.RemoteIP, k.IPVer)

		fk := flowKey{
			Protocol:   protocol,
			LocalIP:    localIP,
			RemoteIP:   remoteIP,
			RemotePort: k.RemotePort,
		}

		if _, exists := flowMap[fk]; !exists {
			flowMap[fk] = &model.FlowDetail{
				Protocol:          protocol,
				LocalIP:           localIP,
				RemoteIP:          remoteIP,
				RemotePort:        k.RemotePort,
				Duration:          0, // Will settle min/max strategy
				ActiveConnections: 0,
			}
		}

		// Aggregation
		f := flowMap[fk]
		f.TotalDownload += v.TxBytes   // Absolute Total
		f.TotalUpload += v.RxBytes     // Absolute Total
		f.SessionDownload += sessionTx // Session Delta
		f.SessionUpload += sessionRx   // Session Delta
		f.DownloadSpeed += speed.TxBytes
		f.UploadSpeed += speed.RxBytes
		f.ActiveConnections++ // Count this connection

		// Duration: Cap by Client Session Start Time
		// If Flow started BEFORE this session reset, Duration = Now - SessionStart
		// If Flow started AFTER this session reset, Duration = Now - FlowStart
		flowStart := a.flowStartTimes[k]
		clientStart := a.clientStartTimes[macStr]

		effectiveStart := flowStart
		if flowStart.Before(clientStart) {
			effectiveStart = clientStart
		}

		if !effectiveStart.IsZero() {
			dur := uint64(time.Since(effectiveStart).Seconds())
			if dur > f.SessionDuration {
				f.SessionDuration = dur
			}
		}

		// Total Duration (Lifetime)
		if !flowStart.IsZero() {
			dur := uint64(time.Since(flowStart).Seconds())
			if dur > f.Duration {
				f.Duration = dur
			}
		}
	}

	var flows []model.FlowDetail
	for _, f := range flowMap {
		flows = append(flows, *f)
	}

	return flows
}

func (a *Aggregator) GetGlobalStats() model.GlobalStats {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.globalStats
}

func (a *Aggregator) GetClient(mac string) *model.ClientStats {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if s, ok := a.display[mac]; ok {
		// Return a copy to avoid race conditions if caller modifies it (though ClientStats is mostly plain data)
		// actually returning pointer is risky if we didn't have locks, but here we return a pointer to the map value.
		// The map value is a pointer `*model.ClientStats`.
		// It's better to return a copy of the ClientStats struct.
		val := *s
		return &val
	}
	return nil
}

func (a *Aggregator) GetClientWithSession(mac string) *model.ClientStats {
	a.mu.Lock()
	defer a.mu.Unlock()

	s, ok := a.display[mac]
	if !ok {
		return nil
	}
	a.clientWatchList[mac] = time.Now()

	// Baseline Logic
	baseline, ok := a.clientBaselines[mac]
	if !ok {
		// Default to global stats (baseline 0) if no explicit session reset has occurred
		baseline = model.ClientStats{}
	}

	// Create a copy to return
	val := *s

	// Calculate Session Totals
	val.SessionDownload = 0
	if s.TotalDownload > baseline.TotalDownload {
		val.SessionDownload = s.TotalDownload - baseline.TotalDownload
	}
	val.SessionUpload = 0
	if s.TotalUpload > baseline.TotalUpload {
		val.SessionUpload = s.TotalUpload - baseline.TotalUpload
	}

	return &val
}

func (a *Aggregator) GetClients() []model.ClientStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make([]model.ClientStats, 0, len(a.display))
	for _, s := range a.display {
		result = append(result, *s)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].DownloadSpeed > result[j].DownloadSpeed
	})

	return result
}

func (a *Aggregator) GetStartTime() time.Time {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.startTime
}

func (a *Aggregator) getHostName(mac string) string {
	if name, ok := a.hostnameMap[mac]; ok {
		return name
	}
	return mac
}

// Map Protocol Number to Name
func protoName(p uint8) string {
	switch p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 58:
		return "ICMP"
	default:
		return "OTHER"
	}
}
