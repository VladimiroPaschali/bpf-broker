#!/bin/bash

# List of maps to dump
maps=("publish_counter" "clone_counter")

for map in "${maps[@]}"; do
    output_file="${map}.csv"
    echo "Dumping $map into $output_file"
    
    # Dump the map and write each value on a new line in the file
    sudo bpftool map dump name "$map" \
        | jq -r '.[0].values | sort_by(.cpu) | .[].value' \
        > "$output_file"
done
