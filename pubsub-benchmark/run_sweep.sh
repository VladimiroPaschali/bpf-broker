#!/usr/bin/env bash
set -euo pipefail

BINARY="./target/release/pubsub-benchmark"
TOPIC="2test"
PUBS=1
BROKER_IP="192.168.101.1"
DURATION=10
OUTPUT="results_$(date +%Y%m%d_%H%M%S).csv"

SUBS_LIST=(1 2 4 8 16 32 64)
SIZE_LIST=(64)

# Limit TX to keep bandwidth well below link capacity (adjust for your NIC).
# Formula: RATE_PPS * SIZE * 8 / 1e6 = Mbit/s
# Example: 300000 * 256 * 8 / 1e6 = 614 Mbit/s  (safe for 1 GbE)
RATE_PPS=0
SINK=1

#lat
# RATE_PPS=128
# SINK=0

echo "size,subs,tx_msgs,tx_msgs_sec,tx_mbit_s,rx_msgs,rx_msgs_sec,rx_mbit_s,lat_received,min_us,max_us,avg_us,p50_us,p90_us,p99_us" > "$OUTPUT"

for SIZE in "${SIZE_LIST[@]}"; do
    for SUBS in "${SUBS_LIST[@]}"; do
        echo ">>> Running: size=${SIZE}B  subs=${SUBS}  rate=${RATE_PPS}pps ..."

        OUTPUT_TMP=$(mktemp)
        SINK_FLAG=()
        [[ "${SINK:-0}" == "1" ]] && SINK_FLAG=(--sink)
        "$BINARY" \
            --topic "$TOPIC" \
            --subs "$SUBS" \
            --pubs "$PUBS" \
            --size "$SIZE" \
            --broker-ip "$BROKER_IP" \
            --duration "$DURATION" \
            --rate-pps "$RATE_PPS" \
            "${SINK_FLAG[@]}" \
            2>&1 | tee "$OUTPUT_TMP"

        TX_LINE=$(grep -P '^TX:' "$OUTPUT_TMP" || echo "")
        if [[ -n "$TX_LINE" ]]; then
            TX_MSGS=$(    echo "$TX_LINE" | grep -oP '[0-9]+(?= msgs)'   | head -1)
            TX_MSGS_SEC=$(echo "$TX_LINE" | grep -oP '[0-9.]+(?= msgs/sec)')
            TX_MBIT=$(    echo "$TX_LINE" | grep -oP '[0-9.]+(?= Mbit/s)')
        else
            TX_MSGS=0; TX_MSGS_SEC=0; TX_MBIT=0
        fi

        RX_LINE=$(grep -P '^RX:' "$OUTPUT_TMP" || echo "")
        if [[ -n "$RX_LINE" ]]; then
            RX_MSGS=$(    echo "$RX_LINE" | grep -oP '[0-9]+(?= msgs)'   | head -1)
            RX_MSGS_SEC=$(echo "$RX_LINE" | grep -oP '[0-9.]+(?= msgs/sec)')
            RX_MBIT=$(    echo "$RX_LINE" | grep -oP '[0-9.]+(?= Mbit/s)')
        else
            RX_MSGS=0; RX_MSGS_SEC=0; RX_MBIT=0
        fi

        LAT_LINE=$(grep -oP 'Latency \(us\):.*' "$OUTPUT_TMP" || echo "")
        if [[ -n "$LAT_LINE" ]]; then
            LAT_RECEIVED=$(echo "$LAT_LINE" | grep -oP 'received=\K[0-9]+')
            MIN_US=$(      echo "$LAT_LINE" | grep -oP 'min=\K[0-9]+')
            MAX_US=$(      echo "$LAT_LINE" | grep -oP 'max=\K[0-9]+')
            AVG_US=$(      echo "$LAT_LINE" | grep -oP 'avg=\K[0-9.]+')
            P50_US=$(      echo "$LAT_LINE" | grep -oP 'p50=\K[0-9.]+')
            P90_US=$(      echo "$LAT_LINE" | grep -oP 'p90=\K[0-9.]+')
            P99_US=$(      echo "$LAT_LINE" | grep -oP 'p99=\K[0-9.]+')
        else
            LAT_RECEIVED=0; MIN_US=0; MAX_US=0; AVG_US=0; P50_US=0; P90_US=0; P99_US=0
        fi

        rm -f "$OUTPUT_TMP"

        echo "$SIZE,$SUBS,$TX_MSGS,$TX_MSGS_SEC,$TX_MBIT,$RX_MSGS,$RX_MSGS_SEC,$RX_MBIT,$LAT_RECEIVED,$MIN_US,$MAX_US,$AVG_US,$P50_US,$P90_US,$P99_US" >> "$OUTPUT"
        echo "    -> TX=${TX_MSGS_SEC} msgs/sec  RX=${RX_MSGS_SEC} msgs/sec  p99=${P99_US}us"
        echo ""
    done
done

echo "=== Done. Results saved to $OUTPUT ==="
