#!/bin/bash

echo "Disabling Hyper-Threading (logical siblings)..."

for path in /sys/devices/system/cpu/cpu*/topology/thread_siblings_list; do
    siblings=$(cat "$path")
    primary=$(echo "$siblings" | cut -d',' -f1)

    for sib in $(echo "$siblings" | tr ',' ' '); do
        if [[ "$sib" != "$primary" && -e /sys/devices/system/cpu/cpu$sib/online ]]; then
            echo 0 | sudo tee /sys/devices/system/cpu/cpu$sib/online > /dev/null
            echo "[OFF] Disabled CPU $sib"
        fi
    done
done

echo "✅ Hyper-Threading disabled. Only primary cores are online."
echo ""
echo "Thread siblings list after disabling:"
for cpu in /sys/devices/system/cpu/cpu*/topology/thread_siblings_list; do
    echo "$cpu → $(cat "$cpu")"
done

#  lscpu | grep -E '^CPU\(s\)|^Thread|Core|Socket'
