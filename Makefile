SHELL := /bin/bash
.PHONY: all deps deps-mac proto generate vmlinux vmlinux-docker \
        build build-go build-agent build-linux build-linux-go build-linux-agent \
        test deploy-a deploy-agent deploy-b deploy-ca-cert deploy-certs experiment docker-build clean

BINARY_DIR := bin
GO         := $(shell command -v go 2>/dev/null || echo go)

# Overridable at the command line
VM_A     ?=                          # service-a VM IP, e.g. 192.168.122.9
VMS      ?=                          # service-b VM IPs, e.g. "192.168.122.10 192.168.122.11"
BRIDGE   ?= virbr0                   # KVM host bridge interface
SSH_USER ?= ubuntu

# ----------------------------------------------------------------------------
# Platform detection — sets BPF_CLANG and BPF_EXTRA_INCLUDES automatically.
# Override at the command line if needed:
#   make generate BPF_CLANG=/usr/bin/clang-17
# ----------------------------------------------------------------------------
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    BREW_PREFIX       := $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)
    BPF_CLANG         ?= $(BREW_PREFIX)/opt/llvm/bin/clang
    export BPF_EXTRA_INCLUDES := -I$(BREW_PREFIX)/include
else
    BPF_CLANG         ?= clang
    export BPF_EXTRA_INCLUDES :=
endif

all: build

# ----------------------------------------------------------------------------
# Build dependencies — run on Linux (VM 0) before make generate / make build
# ----------------------------------------------------------------------------
deps:
	@command -v go >/dev/null 2>&1 || { \
		echo "Go not found — installing via snap..."; \
		sudo snap install go --classic; \
	}
	sudo apt-get install -y \
		clang llvm libbpf-dev linux-headers-$(shell uname -r) \
		build-essential libelf-dev zlib1g-dev protobuf-compiler \
		linux-tools-$(shell uname -r) linux-tools-common
	$(GO) install github.com/cilium/ebpf/cmd/bpf2go@latest
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# macOS dependencies for eBPF code generation and cross-compilation
deps-mac:
	brew install llvm libbpf
	$(GO) install github.com/cilium/ebpf/cmd/bpf2go@latest
	@echo ""
	@echo "Homebrew LLVM clang is at: $(BREW_PREFIX)/opt/llvm/bin/clang"
	@echo "BPF_CLANG and BPF_EXTRA_INCLUDES are set automatically by this Makefile."
	@echo ""
	@echo "Next steps:"
	@echo "  make vmlinux-docker  # generate vmlinux.h via Docker (no Linux machine needed)"
	@echo "  make generate        # compile eBPF C → embedded ELF"
	@echo "  make build-linux     # cross-compile all binaries for Linux x86_64"

# ----------------------------------------------------------------------------
# Proto generation (macOS or Linux — requires protoc)
# ----------------------------------------------------------------------------
proto:
	protoc \
		--go_out=proto --go_opt=paths=source_relative \
		--go-grpc_out=proto --go-grpc_opt=paths=source_relative \
		-I proto \
		proto/stream/stream.proto

# ----------------------------------------------------------------------------
# eBPF code generation
# Linux: run after make deps + make vmlinux
# macOS: run after make deps-mac; vmlinux.h must exist (copy from a Linux machine)
# ----------------------------------------------------------------------------

# Generate vmlinux.h from the running kernel's BTF (Linux only, requires bpftool).
# Prefer 'make vmlinux-docker' which works on macOS and Linux without bpftool installed.
vmlinux:
	@[ -f /sys/kernel/btf/vmlinux ] || \
		(echo "ERROR: /sys/kernel/btf/vmlinux not found — kernel BTF required" >&2; exit 1)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf-agent/bpf/headers/vmlinux.h
	@echo "Generated ebpf-agent/bpf/headers/vmlinux.h"

# Generate vmlinux.h using Docker — works on Linux and macOS (Docker Desktop).
# Uses --privileged so the container can read /sys/kernel/btf/vmlinux directly.
# On macOS, Docker Desktop's Linux VM kernel is used — valid for CO-RE deployment.
vmlinux-docker:
	docker run --rm --privileged \
		-v "$(CURDIR)/ebpf-agent/bpf/headers":/output \
		alpine:3.19 \
		sh -c "apk add --no-cache bpftool >/dev/null 2>&1 && \
		       bpftool btf dump file /sys/kernel/btf/vmlinux format c > /output/vmlinux.h"
	@echo "Generated ebpf-agent/bpf/headers/vmlinux.h via Docker"

# Compile eBPF C programs → Go-embedded ELF (bpf2go + clang with BPF target).
# Works on macOS with Homebrew LLVM; BPF_CLANG/BPF_EXTRA_INCLUDES set above.
generate:
	@[ -f ebpf-agent/bpf/headers/vmlinux.h ] || \
		(echo "ERROR: vmlinux.h missing — run 'make vmlinux-docker' (any OS) or 'make vmlinux' (Linux)" >&2; exit 1)
	cd ebpf-agent && CC=$(BPF_CLANG) $(GO) generate ./internal/loader/...

# ----------------------------------------------------------------------------
# Build targets — native (current platform)
# ----------------------------------------------------------------------------

# Full build: eBPF generation + all native binaries (Linux / VM 0 only)
build: generate build-go build-agent

# Pure-Go native build: service-a, service-b, fault-injector
build-go:
	mkdir -p $(BINARY_DIR)
	$(GO) build -o $(BINARY_DIR)/service-a      ./service-a
	$(GO) build -o $(BINARY_DIR)/service-b      ./service-b
	$(GO) build -o $(BINARY_DIR)/fault-injector ./fault-injector

# eBPF agent native build (requires bpf2go generated files from make generate)
build-agent:
	mkdir -p $(BINARY_DIR)
	$(GO) build -o $(BINARY_DIR)/ebpf-agent ./ebpf-agent

# ----------------------------------------------------------------------------
# Cross-compile targets — Linux x86_64 binaries, output to bin/linux/
# Use these to pre-build on macOS and deploy to VMs without compiling on them.
# ----------------------------------------------------------------------------

# Cross-compile pure-Go binaries for Linux x86_64 (no eBPF dependency)
build-linux-go:
	mkdir -p $(BINARY_DIR)/linux
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		$(GO) build -o $(BINARY_DIR)/linux/service-a      ./service-a
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		$(GO) build -o $(BINARY_DIR)/linux/service-b      ./service-b
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		$(GO) build -o $(BINARY_DIR)/linux/fault-injector ./fault-injector

# Cross-compile ebpf-agent for Linux x86_64 (requires make generate first)
build-linux-agent:
	@ls ebpf-agent/internal/loader/*_bpfel.go > /dev/null 2>&1 || \
		(echo "ERROR: bpf2go generated files missing — run 'make generate' first" >&2; exit 1)
	mkdir -p $(BINARY_DIR)/linux
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		$(GO) build -o $(BINARY_DIR)/linux/ebpf-agent ./ebpf-agent

# Cross-compile all four binaries for Linux x86_64
build-linux: build-linux-go build-linux-agent

# ----------------------------------------------------------------------------
# Tests (pure-Go packages — runs on macOS or Linux)
# ----------------------------------------------------------------------------
test:
	$(GO) test ./service-a/...
	$(GO) test ./service-b/...
	$(GO) test ./fault-injector/...
	$(GO) test ./ebpf-agent/internal/tracker/...

# ----------------------------------------------------------------------------
# Deploy — copies pre-built Linux binaries to VMs and restarts systemd units.
# Cross-compile first: make build-linux (or make build-linux-go / build-linux-agent)
# Usage: make deploy-a VM_A=192.168.122.9
# ----------------------------------------------------------------------------
deploy-a: build-linux-go
	@[ -n "$(VM_A)" ] || (echo "ERROR: VM_A is required, e.g. VM_A=192.168.122.9"; exit 1)
	echo "Deploying service-a to $(VM_A)..."
	scp $(BINARY_DIR)/linux/service-a $(SSH_USER)@$(VM_A):~/service-a
	ssh $(SSH_USER)@$(VM_A) "sudo mv ~/service-a /usr/local/bin/service-a && sudo chmod 755 /usr/local/bin/service-a && sudo systemctl restart service-a"

deploy-agent: build-linux-agent
	@[ -n "$(VM_A)" ] || (echo "ERROR: VM_A is required, e.g. VM_A=192.168.122.9"; exit 1)
	echo "Deploying ebpf-agent to $(VM_A)..."
	scp $(BINARY_DIR)/linux/ebpf-agent $(SSH_USER)@$(VM_A):~/ebpf-agent
	ssh $(SSH_USER)@$(VM_A) "sudo mv ~/ebpf-agent /usr/local/bin/ebpf-agent && sudo chmod 755 /usr/local/bin/ebpf-agent && sudo systemctl restart ebpf-agent"

deploy-b: build-linux-go
	@[ -n "$(VMS)" ] || (echo "ERROR: VMS is required, e.g. VMS=\"192.168.122.10 192.168.122.11\""; exit 1)
	@for vm in $(VMS); do \
		echo "Deploying service-b to $$vm..."; \
		scp $(BINARY_DIR)/linux/service-b $(SSH_USER)@$$vm:~/service-b; \
		ssh $(SSH_USER)@$$vm "sudo mv ~/service-b /usr/local/bin/service-b && sudo chmod 755 /usr/local/bin/service-b && sudo systemctl restart service-b"; \
	done

# Deploy TLS certs to service-b VMs.
# /etc/nginx/certs/ is root-owned, so we scp to ~/ then sudo mv into place.
# Usage: make deploy-certs VMS="192.168.122.10 192.168.122.11"
# Deploy CA cert to service-a VM.
# /etc/service-a/ is root-owned, so we scp to ~/ then sudo mv into place.
# Usage: make deploy-ca-cert VM_A=192.168.122.9
deploy-ca-cert:
	@[ -n "$(VM_A)" ] || (echo "ERROR: VM_A is required"; exit 1)
	@[ -f certs/ca.crt ] || (echo "ERROR: certs/ca.crt not found — run ./certs/gen-certs.sh first"; exit 1)
	scp certs/ca.crt $(SSH_USER)@$(VM_A):~/ca.crt
	ssh $(SSH_USER)@$(VM_A) "sudo mkdir -p /etc/service-a && sudo mv ~/ca.crt /etc/service-a/ca.crt && sudo chmod 644 /etc/service-a/ca.crt"

deploy-certs:
	@[ -n "$(VMS)" ] || (echo "ERROR: VMS is required, e.g. VMS=\"192.168.122.10 192.168.122.11\""; exit 1)
	@for vm in $(VMS); do \
		echo "Deploying certs to $$vm..."; \
		scp certs/$$vm/server.crt $(SSH_USER)@$$vm:~/server.crt; \
		scp certs/$$vm/server.key $(SSH_USER)@$$vm:~/server.key; \
		ssh $(SSH_USER)@$$vm "sudo mkdir -p /etc/nginx/certs \
			&& sudo mv ~/server.crt /etc/nginx/certs/server.crt \
			&& sudo mv ~/server.key /etc/nginx/certs/server.key \
			&& sudo chmod 644 /etc/nginx/certs/server.crt \
			&& sudo chmod 600 /etc/nginx/certs/server.key \
			&& sudo systemctl restart nginx"; \
	done

# ----------------------------------------------------------------------------
# Run the full experiment
# Fault injector runs on the KVM host; service-a is SSH-controlled on VM 0.
# Usage: make experiment BRIDGE=virbr0 VM_A=192.168.122.9 VMS="192.168.122.10 192.168.122.11"
# ----------------------------------------------------------------------------
experiment:
	@[ -n "$(VM_A)" ]   || (echo "ERROR: VM_A required (service-a VM IP)"; exit 1)
	@[ -n "$(VMS)" ]    || (echo "ERROR: VMS required (service-b VM IPs)"; exit 1)
	@[ -n "$(BRIDGE)" ] || (echo "ERROR: BRIDGE required"; exit 1)
	scripts/run-experiment.sh "$(BRIDGE)" "$(VM_A)" $(VMS)

# ----------------------------------------------------------------------------
# Build Docker images for local testing (Linux only — requires BTF kernel).
# Generates vmlinux.h from the running kernel if not already present.
# Usage: make docker-build
# ----------------------------------------------------------------------------
docker-build:
	@[ -f ebpf-agent/bpf/headers/vmlinux.h ] || \
		(echo "vmlinux.h not found — generating via Docker..." && $(MAKE) vmlinux-docker)
	docker compose --profile fault build

# ----------------------------------------------------------------------------
# Clean
# ----------------------------------------------------------------------------
clean:
	rm -rf $(BINARY_DIR)
	rm -f ebpf-agent/internal/loader/*_bpfel.go ebpf-agent/internal/loader/*_bpfeb.go
	rm -f ebpf-agent/bpf/*.o
	rm -f ebpf-agent/bpf/headers/vmlinux.h
