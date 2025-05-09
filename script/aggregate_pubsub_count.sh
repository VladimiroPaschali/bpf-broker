#!/bin/bash

# List of maps to dump
maps=("pub_counter_2" "clone_counter_2")

mkdir -p ../stats

for map in "${maps[@]}"; do
    output_file="../stats/${map}.csv"
    echo "Dumping $map into $output_file"
    
    # Dump the map and write each value on a new line in the file
    sudo bpftool map dump name "$map" \
        | jq -r '.[0].values | sort_by(.cpu) | .[].value' \
        > "$output_file"
done

# Sum all values from both counters
total_publish=$(awk '{sum += $1} END {print sum}' ../stats/pub_counter_2.csv)

# QPS over 30 seconds
qps=$(echo "scale=2; $total_publish / 30" | bc)

# Packet size in bytes (including headers)
PACKET_SIZE=1450

# Convert to Mbps: (qps * PACKET_SIZE * 8) / 1_000_000
mbps=$(echo "scale=2; $qps * $PACKET_SIZE * 8 / 1000000" | bc)

echo "Average QPS over 30s (publish): $qps"
echo "Approximate Mbit/s (publish): $mbps"
