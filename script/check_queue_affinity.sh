#!/bin/bash

IFACE="enp65s0f0np0"
MAX_QUEUES=32

echo "Queue | Type | Queue# | CPU(s)"
echo "-------------------------------"

# Check TX (XPS)
for ((i = 0; i < MAX_QUEUES; i++)); do
    path="/sys/class/net/$IFACE/queues/tx-${i}/xps_cpus"
    if [ -f "$path" ]; then
        hex=$(cat "$path")
        cpus=()
        mask=$((16#${hex}))
        for ((cpu = 0; cpu < 64; cpu++)); do
            if (( (mask & (1 << cpu)) != 0 )); then
                cpus+=($cpu)
            fi
        done
        echo "$IFACE | TX   | $i      | ${cpus[*]}"
    fi
done

# Check RX (IRQ Affinity)
grep -i "mlx5_comp" /proc/interrupts | while read -r line; do
    irq=$(echo "$line" | cut -d: -f1 | xargs)
    desc=$(echo "$line" | awk '{print $NF}')
    queue=$(echo "$desc" | grep -oP 'mlx5_comp\K[0-9]+')
    if [[ -n "$queue" ]]; then
        cpus=()
        counts=$(echo "$line" | cut -d: -f2 | awk '{$1=$1; print}')
        i=0
        for count in $counts; do
            if [[ "$count" != "0" ]]; then
                cpus+=($i)
            fi
            ((i++))
        done
        echo "$IFACE | RX   | $queue | ${cpus[*]}"
    fi
done
