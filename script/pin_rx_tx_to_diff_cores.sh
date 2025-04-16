#!/bin/bash

IFACE="enp8s0d1"

# RX IRQs mapped to RX queues 0–15
RX_IRQS=(52 53 54 55 57 58 59 60 61 62 63 64 65 66 67 68)
NUM_QUEUES=${#RX_IRQS[@]}

echo "Stopping irqbalance..."
sudo systemctl stop irqbalance 2>/dev/null || echo "[WARN] irqbalance not running"

echo ""
echo "Pinning RX IRQs to CPU cores 0–15..."
for ((i=0; i<NUM_QUEUES; i++)); do
    irq=${RX_IRQS[$i]}
    echo "$i" | sudo tee /proc/irq/$irq/smp_affinity_list > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[OK] IRQ $irq (RX queue $i) → CPU $i"
    else
        echo "[ERROR] Failed to pin IRQ $irq"
    fi
done

echo ""
echo "Pinning TX queues 0–15 to CPU cores 16–31..."
for ((i=0; i<NUM_QUEUES; i++)); do
    cpu=$((i + 16))
    mask=$((1 << cpu))
    printf -v hexmask "%x" "$mask"
    echo "$hexmask" | sudo tee /sys/class/net/$IFACE/queues/tx-${i}/xps_cpus > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[OK] TX queue $i → CPU $cpu (mask=0x$hexmask)"
    else
        echo "[ERROR] TX queue $i → failed to write to xps_cpus"
    fi
done

echo ""
echo "Verifying RX and TX queue mappings:"
printf "%-10s %-15s %-15s\n" "Queue" "RX IRQ→CPU" "TX→CPU mask"
for ((i=0; i<NUM_QUEUES; i++)); do
    irq=${RX_IRQS[$i]}
    rx_affinity=$(cat /proc/irq/$irq/smp_affinity_list 2>/dev/null || echo "N/A")
    tx_path="/sys/class/net/$IFACE/queues/tx-${i}/xps_cpus"
    tx_affinity=$(cat "$tx_path" 2>/dev/null || echo "N/A")
    printf "queue%-4d   %-15s %-15s\n" "$i" "$irq→$rx_affinity" "$tx_affinity"
done

echo -e "\n✅ Done. RX queues → CPU 0–15, TX queues → CPU 16–31."
