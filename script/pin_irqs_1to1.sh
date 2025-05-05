#!/bin/bash

set -euo pipefail

IFACE="enp65s0f0np0"
MAX_CORES=16
DEFAULT_COUNT=16

# Parse argument
COUNT=${1:-$DEFAULT_COUNT}
if ! [[ "$COUNT" =~ ^[0-9]+$ ]] || [ "$COUNT" -le 0 ] || [ "$COUNT" -gt "$MAX_CORES" ]; then
    echo "Usage: $0 [count]"
    echo "  count: Number of RX/TX pairs to use (1–$MAX_CORES)"
    exit 1
fi

echo "Configuring $IFACE to use $COUNT combined queues..."
sudo ethtool -L $IFACE combined $COUNT

echo "Stopping irqbalance..."
sudo systemctl stop irqbalance 2>/dev/null || echo "[WARN] irqbalance not running"

echo -e "\nDiscovering mlx5_compX IRQs for interface $IFACE..."

# Get PCI bus info for the interface
NIC_PCI=$(ethtool -i "$IFACE" | awk '/bus-info:/ {print $2}')
if [ -z "$NIC_PCI" ]; then
    echo "[ERROR] Could not get PCI bus info for $IFACE"
    exit 1
fi

# Find all IRQs for mlx5_compX matching the interface
IRQ_LINES=($(grep "mlx5_comp.*$NIC_PCI" /proc/interrupts | awk -F: '{print $1}' | tr -d ' '))

if [ "${#IRQ_LINES[@]}" -lt "$COUNT" ]; then
    echo "[ERROR] Found only ${#IRQ_LINES[@]} IRQs, but need at least $COUNT"
    exit 1
fi

echo "Pinning $COUNT RX IRQs to CPU cores 0–$((COUNT - 1))..."
for ((i = 0; i < COUNT; i++)); do
    IRQ="${IRQ_LINES[$i]}"
    MASK=$((1 << i))
    printf -v HEXMASK "%x" "$MASK"
    echo "$HEXMASK" | sudo tee /proc/irq/$IRQ/smp_affinity > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[OK] IRQ $IRQ (RX queue $i) → CPU $i (mask=0x$HEXMASK)"
    else
        echo "[ERROR] Failed to pin IRQ $IRQ"
    fi
done

echo -e "\nPinning TX queues 0–$((COUNT - 1)) via XPS to CPU cores..."
for ((i = 0; i < COUNT; i++)); do
    MASK=$((1 << i))
    printf -v HEXMASK "%x" "$MASK"
    echo "$HEXMASK" | sudo tee /sys/class/net/$IFACE/queues/tx-${i}/xps_cpus > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[OK] TX queue $i → CPU $i (mask=0x$HEXMASK)"
    else
        echo "[ERROR] TX queue $i → failed to write to xps_cpus"
    fi
done

echo -e "\nRX/TX queues 0–$((COUNT - 1)) pinned to CPU cores 0–$((COUNT - 1))."

for ((i = 0; i < COUNT; i++)); do
    MASK=$((1 << i))
    printf -v HEXMASK "%x" "$MASK"
    echo "$HEXMASK" | sudo tee /sys/class/net/$IFACE/queues/rx-${i}/rps_cpus > /dev/null
    echo "[OK] RX queue $i → RPS set to CPU $i (mask=0x$HEXMASK)"
done

echo 32767 | sudo tee /proc/sys/net/core/rps_sock_flow_entries > /dev/null

echo -e "\nRPS entries set to 32767."

echo -e "\nDone."
