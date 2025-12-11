#!/bin/bash
set -e

# Detect architecture-specific include path for Debian/Ubuntu systems
ARCH=$(uname -m)
INCLUDE_PATH=""

if [ -d "/usr/include/${ARCH}-linux-gnu" ]; then
    INCLUDE_PATH="-I/usr/include/${ARCH}-linux-gnu"
fi

# Run bpf2go with the detected flags
echo "Generating BPF for ${ARCH} with flags: ${INCLUDE_PATH}"
go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "${INCLUDE_PATH}" -no-strip monitor ../../bpf/monitor.bpf.c
