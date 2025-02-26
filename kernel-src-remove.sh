#!/bin/bash
# --------------------
# Run this script to delete downloaded kernel sources
# --------------------
source "$(dirname "$(readlink -f "$0")")/env.sh"

if [[ -f ${BPF_PUBSUB_KERNEL_TARXZ} ]]; then
    echo "Deleting ${BPF_PUBSUB_KERNEL_TARXZ}"
    rm -rf ${BPF_PUBSUB_KERNEL_TARXZ}
fi

if [[ -d "${BPF_PUBSUB_BMC_PATH}/linux" ]]; then
    echo "Deleting ${BPF_PUBSUB_BMC_PATH}/linux"
    rm -rf "${BPF_PUBSUB_BMC_PATH}/linux"
fi

echo "Finished cleaning up."
