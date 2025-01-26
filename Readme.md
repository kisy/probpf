# probpf

probpf is a host network activity monitoring tool designed for routers, built with eBPF and Go. It provides real-time tracking of network connections and traffic statistics.

## Features

- Monitor network traffic using eBPF (both XDP and TC)
- Track IPv4 and IPv6 connections
- Support for TCP and UDP protocols
- Real-time CLI display with host activity statistics
- Prometheus metrics integration
- Efficient connection tracking with automatic cleanup

## Prerequisites

- Linux kernel >= 5.4
- LLVM/Clang for eBPF compilation
- Go >= 1.19
- Router with eBPF support

## Installation

1. Clone the repository:
```bash
git clone https://github.com/kisy/probpf.git
cd probpf
```

2. Required dependencies:
```bash
apt-get install clang llvm libelf-dev gcc-multilib
```

3. Generate eBPF code:
```bash
go generate ./...
```

4. Build the project:
```bash
go build
```

## Usage

### Basic CLI Mode

Run with default interface (br0):
```bash
sudo ./probpf
```

Specify a different network interface:
```bash
sudo ./probpf -i eth0
```

### Prometheus Mode

Start with Prometheus metrics enabled:
```bash
sudo ./probpf -i br0 -p 127.0.0.1:9092
```

## Command Line Options

- `-i string`: Interface to monitor (default "br0")
- `-p string`: Prometheus metrics address (default ":9092")
- `-x string`: XDP mode (auto, generic, driver, offload)
- `-s integer`: Stats sync interval in seconds

## Metrics

When running in Prometheus mode, the following metrics are exposed:

- `probpf_rx_bytes`: Number of bytes received since last scrape
- `probpf_tx_bytes`: Number of bytes transmitted since last scrape

Metrics include the following labels:
- `host`: Local MAC address
- `ip`: Local IP address
- `port`: Local port
- `remote_ip`: Remote IP address
- `remote_port`: Remote port
- `proto`: Protocol (TCP/UDP)
- `timestamp`: Unix timestamp

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT