#!/bin/bash
set -e

echo "Generating BPF..."
go generate ./pkg/bpf/...

echo "Building for AMD64..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/probpf-amd64 ./cmd/probpf

echo "Building for ARM64..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/probpf-arm64 ./cmd/probpf

echo "Done. Binaries in bin/"
ls -lh bin/
