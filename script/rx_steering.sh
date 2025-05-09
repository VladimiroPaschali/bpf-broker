#!/bin/bash

IFACE="enp65s0f0np0"  # Replace with your NIC name (e.g., enp65s0f0np0)
START_PORT=49152

# Enable ntuple filtering (if supported)
echo "[*] Enabling ntuple filtering on $IFACE..."
ethtool -K $IFACE ntuple on 2>/dev/null || echo "[!] Failed to enable ntuple (may already be on or unsupported)"

# Add rules
for ((i=0; i<16; i++)); do
    PORT=$((START_PORT + i))
    QUEUE=$i
    echo "[*] Assigning dst-port $PORT to RX queue $QUEUE..."
    # ethtool -N $IFACE flow-type tcp4 dst-port $PORT action $QUEUE 2>/dev/null

    # Uncomment below for UDP:
    ethtool -N $IFACE flow-type udp4 dst-port $PORT action $QUEUE
done

# Verify rules
echo "[*] Verifying applied RX steering rules..."
ethtool -n $IFACE rx-flow-hash tcp4
ethtool -n $IFACE
