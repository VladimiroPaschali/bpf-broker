#!/bin/bash

set -euo pipefail

IFACE="enp8s0d1"
BPF_PIN_PATH="/sys/fs/bpf/tc_ingress_logger"

echo "Step 1: Removing existing filters (if any)..."
sudo tc filter del dev "$IFACE" ingress

echo "Step 2: Removing existing clsact qdisc (if any)..."
sudo tc qdisc del dev "$IFACE" clsact

echo "Step 3: Adding clsact qdisc to $IFACE..."
sudo tc qdisc add dev "$IFACE" clsact

echo "Step 4: Attaching pinned BPF program from $BPF_PIN_PATH..."
if [[ ! -e "$BPF_PIN_PATH" ]]; then
    echo "Error: BPF program not pinned at $BPF_PIN_PATH"
    exit 1
fi
sudo tc filter add dev "$IFACE" ingress bpf object-pinned "$BPF_PIN_PATH"

echo "Step 5: Showing active filters on $IFACE:"
sudo tc filter show dev "$IFACE" ingress

echo -e "\nStep 6: Streaming trace output (Ctrl+C to stop):"
sudo cat /sys/kernel/debug/tracing/trace_pipe


# sudo tc qdisc add dev enp8s0d1 clsact
# sudo ls /sys/fs/bpf
# sudo tc filter add dev enp8s0d1 ingress bpf object-pinned /sys/fs/bpf/tc_ingress_logger 
# tc filter show dev enp8s0d1 ingress

# sudo tc filter del dev enp8s0d1 ingress
# sudo tc qdisc del dev enp8s0d1 clsact
# sudo cat /sys/kernel/debug/tracing/trace_pipe
