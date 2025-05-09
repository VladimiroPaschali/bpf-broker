#!/bin/bash

# Usage: ./set_tc_pps.sh <pps> <packet_size_bytes>
# Example: ./set_tc_pps.sh 1000000 1450

IFACE="enp65s0f0np0"
PPS="$1"
PAYLOAD_SIZE="$2"

if [ -z "$PPS" ] || [ -z "$PAYLOAD_SIZE" ]; then
    echo "Usage: $0 <pps> <payload_size_bytes>"
    exit 1
fi

PKT_SIZE=$((PAYLOAD_SIZE + 28))
RATE_MBPS=$((PPS * PKT_SIZE * 8 / 1000000))

echo "[*] Applying fq qdisc on $IFACE with maxrate ${RATE_MBPS}mbit..."

# Clear existing qdisc
sudo tc qdisc del dev "$IFACE" root 2>/dev/null
sudo tc qdisc add dev "$IFACE" root fq maxrate "${RATE_MBPS}mbit"

echo "[✓] fq qdisc applied on $IFACE at ~${RATE_MBPS} Mbit/sec"
