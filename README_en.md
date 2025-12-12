# probpf

**English** | [中文](README.md)

ProBPF is a high-performance host network activity monitoring tool built with eBPF and Go. It provides real-time tracking of network connections, traffic statistics, and per-flow analysis, visualized through a modern, mobile-responsive Web UI.

## Features

- **eBPF Monitoring**: Efficiently tracks IPv4/IPv6 TCP and UDP traffic using XDP and TC.
- **Real-time Web UI**:
  - **Dashboard**: Overview of all active clients with sorting and search.
  - **Client Details**: Deep dive into per-connection (flow) statistics.
  - **Session & Global Stats**: Track bandwidth usage for the current session vs. historical totals.
  - **Mobile Optimized**: Fully responsive design with card views and optimized controls for mobile devices.
  - **Dark Mode**: Automatic or manual theme switching.
- **Advanced Traffic Analysis**:
  - **Flow Duration**: Accurate tracking of connection duration.
  - **Protocol Filtering**: Filter by protocol, remote IP, or port.
  - **CIDR Filtering**: Ignore traffic from specific subnets using `-lan` (auto-detect) or `-cidr` (manual).
- **Resource Efficient**: Automatic connection cleanup and low-overhead eBPF probes.

## Prerequisites

- Linux kernel >= 5.4 (BTF support recommended)
- LLVM/Clang for eBPF compilation
- Go >= 1.21

## Installation

1. Clone the repository:

```bash
git clone https://github.com/kisy/probpf.git
cd probpf
```

2. Install dependencies (Ubuntu/Debian):

```bash
apt-get install clang llvm libbpf-dev
```

3. Build the project (using the provided script):

```bash
./build.sh
```

This script handles eBPF generation and Go compilation for both AMD64 and ARM64 architectures.

## Usage

### Web UI Mode (Recommended)

Start the monitoring agent with the Web UI enabled:

```bash
sudo ./bin/probpf-amd64 -i eth0 --listen :8000
```

access the dashboard at `http://<your-server-ip>:8000`.

### LAN Monitoring & Filtering

By default, ProBPF automatically ignores local LAN traffic.

**Enable LAN Monitoring:**

```bash
sudo ./bin/probpf-amd64 -i eth0 --listen :8000 --lan
```

**Customize Ignored Subnets:**
If NOT using `--lan`, use `--cidr` to manually specify subnets to ignore (overriding auto-detection):

```bash
sudo ./bin/probpf-amd64 -i eth0 --listen :8000 --cidr 192.168.0.0/16
```

## Command Line Options

### Basic Options

| Flag | Long Option          | Description                  | Default  |
| ---- | -------------------- | ---------------------------- | -------- |
| `-i` | `--interface`        | Network interface to monitor | Required |
| `-l` | `--listen`, `--http` | Web server listen address    | `:9092`  |
| `-c` | `--config`           | Configuration file path      | -        |

### Timing Parameters (Smart Defaults)

| Flag  | Long Option       | Description                     | Default                  |
| ----- | ----------------- | ------------------------------- | ------------------------ |
| `-s`  | `--sync-interval` | Data sync interval (seconds)    | `1`                      |
| -     | `--flow-ttl`      | Inactive flow timeout (seconds) | `300`                    |
| `-gc` | `--gc-ttl`        | Cleanup interval (seconds)      | **Auto** = flow-ttl/5    |
| -     | `--client-ttl`    | Client cache TTL (seconds)      | **Auto** = flow-ttl\*0.4 |

> 💡 **Smart Defaults**: `--gc-ttl` and `--client-ttl` are automatically calculated from `--flow-ttl`. Most users only need to set `--flow-ttl`.

### Filtering Options

| Flag     | Long Option     | Description                                            | Default     |
| -------- | --------------- | ------------------------------------------------------ | ----------- |
| `--lan`  | `--monitor-lan` | Monitor LAN traffic (disable filtering)                | `false`     |
| `--cidr` | `--local-cidr`  | Local CIDR to ignore (can be specified multiple times) | Auto-detect |

### Advanced Options

| Flag | Long Option  | Description                               | Default |
| ---- | ------------ | ----------------------------------------- | ------- |
| `-x` | `--xdp-mode` | XDP mode (auto, generic, driver, offload) | `auto`  |

### Usage Examples

**Basic startup (recommended):**

```bash
sudo ./bin/probpf-amd64 -i eth0
# Uses all default values, simple and fast
```

**Custom flow timeout:**

```bash
sudo ./bin/probpf-amd64 -i eth0 --flow-ttl 180
# gc-ttl automatically set to 36 seconds
# client-ttl automatically set to 72 seconds
```

**Low-resource device (e.g., Raspberry Pi):**

```bash
sudo ./bin/probpf-amd64 -i eth0 --flow-ttl 120
# 2-minute timeout, faster memory release
```

## Prometheus Monitoring

ProBPF includes built-in Prometheus metrics export for integration with Grafana.

### Quick Start

**Start Prometheus + Grafana:**

```bash
docker-compose up -d
```

**Access monitoring panels:**

- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (admin/admin)

### Metrics Endpoint

```bash
curl http://localhost:9092/metrics
```

### Exported Metrics

**Global Metrics:**

- `probpf_global_download_bps` - Total download speed
- `probpf_global_upload_bps` - Total upload speed
- `probpf_global_active_connections` - Active connections count
- `probpf_global_active_devices` - Online devices count

**Device-level Metrics:**

- `probpf_device_download_bps{mac, name}` - Device download speed
- `probpf_device_upload_bps{mac, name}` - Device upload speed
- `probpf_device_bytes_total{mac, name, direction}` - Device traffic stats

**Protocol Statistics:**

- `probpf_protocol_bytes_total{protocol, direction}` - Traffic by protocol

### Grafana Dashboard

The project includes a pre-configured Grafana Dashboard (`grafana.json`) featuring:

- Global speed gauges
- Traffic trend charts
- Top 10 device rankings
- Protocol distribution pie charts
- Top 5 device trend comparison

## Web UI Features

- **Client List**: View all active IPs with real-time download/upload speeds.
- **Detail View**:
  - **Session Stats**: Independent session counters (traffic/duration) resetable via specific buttons.
  - **Global Stats**: Historical total traffic counters.
  - **Flow Table**: Live list of all active connections with protocol, remote IPs and ports.
- **Controls**:
  - **Auto-Refresh**: Pause/Resume live updates.
  - **Theme**: Toggle Dark/Light mode.
  - **IP Info**: Select preferred IP geolocation provider (ipinfo.io, ipapi.is, censys.io, etc.).

## License

GPL 2.0
