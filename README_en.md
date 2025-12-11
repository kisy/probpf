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
sudo ./bin/probpf-amd64 -i eth0 -l :8000
```

access the dashboard at `http://<your-server-ip>:8000`.

### LAN Monitoring & Filtering

By default, ProBPF automatically ignores local LAN traffic.

**Enable LAN Monitoring:**

```bash
sudo ./bin/probpf-amd64 -i eth0 -l :8000 -lan
```

**Customize Ignored Subnets:**
If NOT using `-lan`, use `-cidr` to manually specify subnets to ignore (overriding auto-detection):

```bash
sudo ./bin/probpf-amd64 -i eth0 -l :8000 -cidr 192.168.0.0/16
```

## Command Line Options

| Flag    | Description                                        | Default    |
| ------- | -------------------------------------------------- | ---------- |
| `-i`    | Network interface to monitor                       | `br0`      |
| `-l`    | Web UI listen address (e.g., `:8000`)              | (Disabled) |
| `-lan`  | Enable LAN traffic monitoring (ignored by default) | `false`    |
| `-cidr` | Custom subnets to ignore (can be repeated)         | None       |
| `-x`    | XDP mode (auto, generic, driver, offload)          | `auto`     |
| `-s`    | Stats sync interval in seconds                     | `1`        |

## Web UI Features

- **Client List**: View all active IPs with real-time download/upload speeds.
- **Detail View**:
  - **Session Stats**: independent session counters (traffic/duration) resetable via specific buttons.
  - **Global Stats**: Historical total traffic counters.
  - **Flow Table**: Live list of all active connections with localized/remote IPs and ports.
- **Controls**:
  - **Auto-Refresh**: Pause/Resume live updates.
  - **Theme**: Toggle Dark/Light mode.
  - **IP Info**: Select preferred IP geolocation provider (ipinfo.io, ipapi.is, etc.).

## License

GPL 2.0
