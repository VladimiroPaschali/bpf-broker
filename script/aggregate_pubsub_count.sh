#!/bin/bash

# List of maps to dump
maps=("publish_counter" "clone_counter")

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
total_publish=$(awk '{sum += $1} END {print sum}' ../stats/publish_counter.csv)

qps=$(echo "scale=2; $total_publish / 60" | bc)

echo "Average QPS over 60s (publish): $qps"
