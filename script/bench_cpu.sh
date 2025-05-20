#!/bin/bash

duration=28        # total duration in seconds
interval=0.5       # sampling interval in seconds
samples=$(echo "$duration / $interval" | bc)

cpu_utils=()

echo "Collecting CPU usage every $interval s for $duration s..."

prev_idle=0
prev_total=0

get_cpu_util() {
    # Read first line of /proc/stat
    cpu_line=($(head -n 1 /proc/stat))
    idle=${cpu_line[4]}
    total=0
    for val in "${cpu_line[@]:1}"; do
        total=$((total + val))
    done

    delta_idle=$((idle - prev_idle))
    delta_total=$((total - prev_total))
    cpu_util=$(echo "scale=2; 100 * (1 - $delta_idle / $delta_total)" | bc -l)

    prev_idle=$idle
    prev_total=$total

    echo "$cpu_util"
}

# Initial baseline
read -a cpu_line <<< "$(head -n 1 /proc/stat)"
prev_idle=${cpu_line[4]}
prev_total=0
for val in "${cpu_line[@]:1}"; do
    prev_total=$((prev_total + val))
done

for ((i = 0; i < samples; i++)); do
    sleep $interval
    util=$(get_cpu_util)
    cpu_utils+=("$util")
    # echo "Sample $i: $util%"
done

# Compute average and std deviation
sum=0
for val in "${cpu_utils[@]}"; do
    sum=$(echo "$sum + $val" | bc)
done
avg=$(echo "scale=2; $sum / ${#cpu_utils[@]}" | bc)

sumsq=0
for val in "${cpu_utils[@]}"; do
    diff=$(echo "$val - $avg" | bc)
    diff_sq=$(echo "$diff * $diff" | bc)
    sumsq=$(echo "$sumsq + $diff_sq" | bc)
done
std=$(echo "scale=2; sqrt($sumsq / ${#cpu_utils[@]})" | bc -l)

echo ""
echo "CPU Utilization Summary:"
echo "  Samples: ${#cpu_utils[@]}"
echo "  Average: $avg %"
echo "  Std Dev: $std %"
