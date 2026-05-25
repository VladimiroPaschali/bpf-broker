#!/usr/bin/env bash
set -euo pipefail

BINARY="./target/release/pubsub-benchmark"
TOPIC="2test"
PUBS=1
BROKER_IP="192.168.101.1"
DURATION=10
SUBS_LIST=(1 2 4 8 16 32 64)
SIZE_LIST=(64)

# ── Mode ──────────────────────────────────────────────────────────────────────
# Set MODE="RATE_PPS" to send at a fixed rate (default).
# Set MODE="NDR" to binary-search for the No-Drop Rate per (size, subs) combo.
# MODE="RATE_PPS"
MODE="NDR"

# ── RATE_PPS settings ────────────────────────────────────────────────────────
# Formula: RATE_PPS * SIZE * 8 / 1e6 = Mbit/s
# Example: 15000 * 64 * 8 / 1e6 = 7.68 Mbit/s
RATE_PPS=15000
SINK=1

# ── NDR settings ─────────────────────────────────────────────────────────────
# NDR_MAX_PPS   : upper bound for binary search (pps)
# NDR_TRIAL_SECS: probe duration per iteration (shorter = faster, noisier)
# NDR_TOLERANCE : acceptable drop fraction (0.0 = strict no-drop)
# NDR_ITERATIONS: binary search depth (10 → ~0.1% precision of the range)
NDR_MAX_PPS=2000000
NDR_MIN_PPS=0
NDR_TRIAL_SECS=5
NDR_TOLERANCE=0.01
NDR_ITERATIONS=20

#lat
# MODE="RATE_PPS"
# RATE_PPS=10000
# SINK=0

# ── Output file ───────────────────────────────────────────────────────────────
OUTPUT="${MODE}_results_$(date +%Y%m%d_%H%M%S).csv"

if [[ "$MODE" == "NDR" ]]; then
    echo "size,subs,ndr_pps,tx_msgs,tx_msgs_sec,tx_mbit_s,rx_msgs,rx_msgs_sec,rx_mbit_s,lat_received,min_us,max_us,avg_us,p50_us,p90_us,p99_us" > "$OUTPUT"
else
    echo "size,subs,tx_msgs,tx_msgs_sec,tx_mbit_s,rx_msgs,rx_msgs_sec,rx_mbit_s,lat_received,min_us,max_us,avg_us,p50_us,p90_us,p99_us" > "$OUTPUT"
fi

for SIZE in "${SIZE_LIST[@]}"; do
    for SUBS in "${SUBS_LIST[@]}"; do
        echo ">>> Flushing broker state for topic '${TOPIC}'..."
        printf "FLUSH %s" "$TOPIC" | nc -u -w1 "$BROKER_IP" 49152 > /dev/null 2>&1
        sleep 0.3

        if [[ "$MODE" == "NDR" ]]; then
            echo ">>> Running NDR search: size=${SIZE}B  subs=${SUBS}  max=${NDR_MAX_PPS}pps ..."
        else
            echo ">>> Running: size=${SIZE}B  subs=${SUBS}  rate=${RATE_PPS}pps ..."
        fi

        OUTPUT_TMP=$(mktemp)
        SINK_FLAG=()
        [[ "${SINK:-0}" == "1" ]] && SINK_FLAG=(--sink)

        if [[ "$MODE" == "NDR" ]]; then
            "$BINARY" \
                --topic "$TOPIC"  \
                --subs "$SUBS" \
                --pubs "$PUBS" \
                --size "$SIZE" \
                --broker-ip "$BROKER_IP" \
                --duration "$DURATION" \
                --ndr \
                --ndr-max-pps "$NDR_MAX_PPS" \
                --ndr-min-pps "$NDR_MIN_PPS" \
                --ndr-tolerance "$NDR_TOLERANCE" \
                --ndr-trial-duration "$NDR_TRIAL_SECS" \
                --ndr-iterations "$NDR_ITERATIONS" \
                "${SINK_FLAG[@]}" \
                2>&1 | tee "$OUTPUT_TMP"
        else
            "$BINARY" \
                --topic "$TOPIC"  \
                --subs "$SUBS" \
                --pubs "$PUBS" \
                --size "$SIZE" \
                --broker-ip "$BROKER_IP" \
                --duration "$DURATION" \
                --rate-pps "$RATE_PPS" \
                "${SINK_FLAG[@]}" \
                2>&1 | tee "$OUTPUT_TMP"
        fi

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

        LAT_LINE=$(grep -oP 'Last-copy latency \(us\):.*' "$OUTPUT_TMP" || echo "")
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

        # Parse NDR rate from the dedicated summary line: "NDR: <pps> pps ..."
        NDR_PPS=0
        if [[ "$MODE" == "NDR" ]]; then
            NDR_LINE=$(grep -P '^NDR:' "$OUTPUT_TMP" | tail -1 || echo "")
            if [[ -n "$NDR_LINE" ]]; then
                NDR_PPS=$(echo "$NDR_LINE" | grep -oP '[0-9]+(?= pps)' | head -1 || echo "0")
            fi
        fi

        rm -f "$OUTPUT_TMP"

        if [[ "$MODE" == "NDR" ]]; then
            echo "$SIZE,$SUBS,$NDR_PPS,$TX_MSGS,$TX_MSGS_SEC,$TX_MBIT,$RX_MSGS,$RX_MSGS_SEC,$RX_MBIT,$LAT_RECEIVED,$MIN_US,$MAX_US,$AVG_US,$P50_US,$P90_US,$P99_US" >> "$OUTPUT"
            echo "    -> NDR=${NDR_PPS}pps  TX=${TX_MSGS_SEC} msgs/sec  RX=${RX_MSGS_SEC} msgs/sec  p99=${P99_US}us"
        else
            echo "$SIZE,$SUBS,$TX_MSGS,$TX_MSGS_SEC,$TX_MBIT,$RX_MSGS,$RX_MSGS_SEC,$RX_MBIT,$LAT_RECEIVED,$MIN_US,$MAX_US,$AVG_US,$P50_US,$P90_US,$P99_US" >> "$OUTPUT"
            echo "    -> TX=${TX_MSGS_SEC} msgs/sec  RX=${RX_MSGS_SEC} msgs/sec  p99=${P99_US}us"
        fi
        echo ""
    done
done

echo "=== Done. Results saved to $OUTPUT ==="
