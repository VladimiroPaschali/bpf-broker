#!/bin/bash

# Usage: ./set_tc_rate_police.sh <rate_mbit>
# Example: ./set_tc_rate_police.sh 1024

IFACE="enp65s0f0np0"
MBPS=$1

if [ -z "$MBPS" ]; then
    echo "Usage: $0 <rate_mbit>"
    exit 1
fi

# Configure burst: allow 10ms worth of traffic
BURST_BYTES=$((MBPS * 1000000 / 8 / 1000))  # 10ms worth of data

echo "[*] Target rate: ${MBPS} mbit/sec"
echo "[*] Burst size: ${BURST_BYTES} bytes (1ms worth)"

# Clear existing config
sudo tc qdisc del dev $IFACE root 2>/dev/null
sudo tc qdisc del dev $IFACE clsact 2>/dev/null

# Attach clsact qdisc
# sudo tc qdisc add dev $IFACE clsact

# # Apply policing on egress
# sudo tc filter add dev $IFACE egress protocol ip prio 1 \
#   u32 match u32 0 0 \
#   police rate ${MBPS}mbit burst ${BURST_BYTES} \
#          peakrate ${MBPS}mbit mtu 1500 drop flowid :1

# echo "[✓] Policing applied on $IFACE to drop above ${MBPS}mbit"
