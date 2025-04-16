#!/bin/bash

IFACE="enp8s0d1"
START_RX_IRQ=52
NUM_QUEUES=16

echo "Stopping irqbalance..."
sudo systemctl stop irqbalance 2>/dev/null || echo "[WARN] irqbalance not running"

echo "Pinning RX IRQs to CPU cores..."
for ((i=0; i<NUM_QUEUES; i++)); do
    irq=$((START_RX_IRQ + i))
    echo "$i" | sudo tee /proc/irq/$irq/smp_affinity_list > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[OK] IRQ $irq (RX queue $i) → CPU $i"
    else
        echo "[ERROR] Failed to pin IRQ $irq"
    fi
done

echo ""
echo "Pinning TX queues via XPS to CPU cores..."
for ((i=0; i<NUM_QUEUES; i++)); do
    mask=$((1 << i))
    printf -v hexmask "%x" "$mask"
    echo "$hexmask" | sudo tee /sys/class/net/$IFACE/queues/tx-${i}/xps_cpus > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[OK] TX queue $i → CPU $i (mask=0x$hexmask)"
    else
        echo "[ERROR] TX queue $i → failed to write to xps_cpus"
    fi
done

echo ""
echo "Verifying RX and TX queue mappings:"
printf "%-10s %-15s %-15s\n" "Queue" "RX IRQ→CPU" "TX→CPU mask"
for ((i=0; i<NUM_QUEUES; i++)); do
    irq=$((START_RX_IRQ + i))
    rx_affinity=$(cat /proc/irq/$irq/smp_affinity_list 2>/dev/null || echo "N/A")
    tx_path="/sys/class/net/$IFACE/queues/tx-${i}/xps_cpus"
    tx_affinity=$(cat "$tx_path" 2>/dev/null || echo "N/A")
    printf "queue%-4d   %-15s %-15s\n" "$i" "$irq→$rx_affinity" "$tx_affinity"
done

echo -e "\nDone. RX and TX queues are pinned 1:1 to CPU cores 0–15."
