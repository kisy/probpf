package model

import "time"

// ClientKey removed - we use MAC string as key

// HostKey maps to the BPF C structure (Raw Key)
// Used in pkg/bpf to read from map.
// Note: We renamed fields to match their actual semantics after BPF logic adjustments.
// Memory layout MUST match C struct order.
type HostKey struct {
	ClientMac  [6]byte
	_          [2]byte // Padding for alignment
	ClientIP   [16]byte
	RemoteIP   [16]byte
	RemotePort uint16
	SrcPort    uint16
	Proto      uint8
	IPVer      uint8
	_          [2]byte // Tail padding to match C struct size (48 bytes)
}

// HostStats maps to the BPF C structure (Raw Stats)
type HostStats struct {
	RxBytes uint64
	TxBytes uint64
}

// ClientStats contains aggregated statistics for a client (MAC-based)
type ClientStats struct {
	MAC               string    `json:"mac"`
	Name              string    `json:"name"`
	TotalDownload     uint64    `json:"total_download"`
	TotalUpload       uint64    `json:"total_upload"`
	SessionDownload   uint64    `json:"session_download"`
	SessionUpload     uint64    `json:"session_upload"`
	DownloadSpeed     uint64    `json:"download_speed"`
	UploadSpeed       uint64    `json:"upload_speed"`
	ActiveConnections uint64    `json:"active_connections"`
	LastUpdate        time.Time `json:"last_update"`
	StartTime         time.Time `json:"start_time"`
	LastActive        time.Time `json:"last_active"`
}

type FlowDetail struct {
	Protocol          string `json:"protocol"`
	RemoteIP          string `json:"remote_ip"`
	RemotePort        uint16 `json:"remote_port"`
	TotalDownload     uint64 `json:"total_download"`
	TotalUpload       uint64 `json:"total_upload"`
	SessionDownload   uint64 `json:"session_download"`
	SessionUpload     uint64 `json:"session_upload"`
	DownloadSpeed     uint64 `json:"download_speed"`
	UploadSpeed       uint64 `json:"upload_speed"`
	Duration          uint64 `json:"duration"`
	SessionDuration   uint64 `json:"session_duration"`
	ActiveConnections uint64 `json:"active_connections"`
}

type GlobalStats struct {
	TotalDownload     uint64 `json:"total_download"`
	TotalUpload       uint64 `json:"total_upload"`
	DownloadSpeed     uint64 `json:"download_speed"`
	UploadSpeed       uint64 `json:"upload_speed"`
	ActiveConnections uint64 `json:"active_connections"`
}
