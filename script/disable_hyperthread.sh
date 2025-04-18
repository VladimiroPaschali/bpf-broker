#!/bin/bash

echo "Disabling Hyper-Threading (logical siblings)..."

for path in /sys/devices/system/cpu/cpu*/topology/thread_siblings_list; do
    cpu_dir=$(basename "$(dirname "$path")") # e.g., cpu16
    siblings=$(cat "$path")
    first=$(echo "$siblings" | cut -d',' -f1)

    # Skip if this is the primary core
    if [[ "$cpu_dir" == "cpu$first" ]]; then
        for sib in $(echo "$siblings" | tr ',' ' '); do
            if [[ "$sib" != "$first" && -e /sys/devices/system/cpu/cpu$sib/online ]]; then
                echo 0 | sudo tee /sys/devices/system/cpu/cpu$sib/online > /dev/null
                echo "[OFF] Disabled CPU $sib"
            fi
        done
    fi
done

echo "✅ Hyper-Threading disabled. Only primary cores are online."

for cpu in /sys/devices/system/cpu/cpu*/topology/thread_siblings_list; do
    echo "$cpu → $(cat $cpu)"
done
