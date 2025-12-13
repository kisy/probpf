#!/bin/bash
set -e

# Detect architecture-specific include path and target for BPF compilation
ARCH=$(uname -m)
INCLUDE_PATH=""
BPF_TARGET=""

# Map host architecture to BPF target
case "${ARCH}" in
    x86_64)
        BPF_TARGET="x86"
        ;;
    aarch64|arm64)
        BPF_TARGET="arm64"
        ;;
    armv7l|armv6l)
        BPF_TARGET="arm"
        ;;
    *)
        echo "Warning: Unknown architecture ${ARCH}, using default"
        BPF_TARGET="bpf"
        ;;
esac

if [ -d "/usr/include/${ARCH}-linux-gnu" ]; then
    INCLUDE_PATH="-I/usr/include/${ARCH}-linux-gnu"
fi

# Generate BPF Logic (Single Build, No CO-RE)
echo "Generating BPF for ${ARCH} with flags: ${INCLUDE_PATH} -target ${BPF_TARGET}"
go run github.com/cilium/ebpf/cmd/bpf2go \
    -cc clang \
    -cflags "${INCLUDE_PATH} -D__TARGET_ARCH_${BPF_TARGET}" \
    -target bpfel,bpfeb \
    -no-strip \
    monitor ../../bpf/monitor.bpf.c
