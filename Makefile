.PHONY: all build-amd64 build-arm64 generate clean

BINARY_NAME=probpf

all: generate build-amd64 build-arm64

generate:
	go generate ./pkg/bpf/...

build-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/$(BINARY_NAME)-amd64 ./cmd/probpf

build-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/$(BINARY_NAME)-arm64 ./cmd/probpf

clean:
	rm -rf bin/
