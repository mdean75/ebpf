#!/usr/bin/env bash
# Entrypoint for the vm0 container.
# Starts ebpf-agent first (requires privileged mode to load eBPF programs),
# waits for it to become ready, then starts service-a in the foreground.
set -e

echo "Starting ebpf-agent..."
/usr/local/bin/ebpf-agent &
AGENT_PID=$!

# Wait for ebpf-agent to load eBPF programs and open its HTTP API.
# Poll /health/all rather than sleeping a fixed duration.
READY=0
for i in $(seq 1 20); do
    if curl -sf --max-time 1 http://localhost:9090/health/all > /dev/null 2>&1; then
        echo "ebpf-agent ready"
        READY=1
        break
    fi
    # Also check that the process is still alive
    if ! kill -0 $AGENT_PID 2>/dev/null; then
        echo "ERROR: ebpf-agent exited unexpectedly" >&2
        exit 1
    fi
    sleep 0.5
done

if [ $READY -eq 0 ]; then
    echo "WARNING: ebpf-agent did not respond within 10s — starting service-a anyway"
fi

echo "Starting service-a..."
exec /usr/local/bin/service-a
