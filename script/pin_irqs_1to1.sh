#!/bin/bash

set -euo pipefail

IFACE="enp65s0f0np0"

echo "Stopping irqbalance..."
sudo systemctl stop irqbalance 2>/dev/null || echo "[WARN] irqbalance not running"

echo -e "\nDiscovering mlx5_compX IRQs for interface $IFACE..."

# Get PCI bus info for the interface
NIC_PCI=$(ethtool -i "$IFACE" | awk '/bus-info:/ {print $2}')
if [ -z "$NIC_PCI" ]; then
    echo "[ERROR] Could not get PCI bus info for $IFACE"
    exit 1
fi

# Parse /proc/interrupts for matching mlx5 IRQs
RX_IRQS=()
while IFS= read -r line; do
    if echo "$line" | grep -q "mlx5_comp" && echo "$line" | grep -q "$NIC_PCI"; then
        irq=$(echo "$line" | cut -d: -f1 | tr -d ' ')
        RX_IRQS+=("$irq")
    fi
done < /proc/interrupts

NUM_QUEUES=${#RX_IRQS[@]}
if [ "$NUM_QUEUES" -eq 0 ]; then
    echo "[ERROR] No mlx5_compX IRQs found for interface $IFACE (PCI $NIC_PCI)"
    exit 1
fi

echo "Pinning $NUM_QUEUES RX IRQs to CPU cores 0–$((NUM_QUEUES - 1))..."
for ((i = 0; i < NUM_QUEUES; i++)); do
    irq="${RX_IRQS[$i]}"
    core="$i"
    mask=$((1 << core))
    printf -v hexmask "%x" "$mask"
    echo "$hexmask" | sudo tee /proc/irq/$irq/smp_affinity > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[OK] IRQ $irq → CPU $core (mask=0x$hexmask)"
    else
        echo "[ERROR] Failed to pin IRQ $irq"
    fi
done

echo -e "\nPinning TX queues via XPS to CPU cores..."
for ((i = 0; i < NUM_QUEUES; i++)); do
    mask=$((1 << i))
    printf -v hexmask "%x" "$mask"
    echo "$hexmask" | sudo tee /sys/class/net/$IFACE/queues/tx-${i}/xps_cpus > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[OK] TX queue $i → CPU $i (mask=0x$hexmask)"
    else
        echo "[ERROR] TX queue $i → failed to write to xps_cpus"
    fi
done

echo -e "\n✅ Done. IRQs and TX queues pinned 1:1 to CPU cores."
