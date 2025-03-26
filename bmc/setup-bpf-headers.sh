#!/bin/bash
mkdir -p linux/tools/include/bpf
for f in linux/tools/lib/bpf/*.h; do
    ln -sf ../../../lib/bpf/$(basename "$f") linux/tools/include/bpf/
done
echo "All bpf/*.h headers linked!"
