import subprocess
import json
from struct import unpack

def get_percpu_map_values(map_name):
    cmd = ["sudo", "bpftool", "-j", "map", "dump", "name", map_name]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"bpftool failed for {map_name}: {result.stderr}")
    data = json.loads(result.stdout)

    for entry in data:
        if "values" in entry:
            flat_values = []
            for cpu_val in entry["values"]:
                val = cpu_val["value"]
                if isinstance(val, int):
                    flat_values.append(val)
                elif isinstance(val, list) and all(isinstance(b, str) and b.startswith("0x") for b in val):
                    byte_vals = bytes(int(b, 16) for b in val)
                    flat_values.append(unpack("<Q", byte_vals)[0])
                else:
                    raise ValueError(f"Unexpected value format: {val}")
            return flat_values
    raise RuntimeError(f"No per-CPU values found in map: {map_name}")

def main():
    clone_counts = get_percpu_map_values("map_clone_count")
    avg_latencies = get_percpu_map_values("avg_latency_tc")
    
    # print(clone_counts)
    # print(avg_latencies)

    total_count = sum(clone_counts)
    weighted_sum = sum(c * l for c, l in zip(clone_counts, avg_latencies))
    global_avg_latency = weighted_sum / total_count if total_count > 0 else 0

    print(f"Total clone count: {total_count}")
    print(f"Global average latency: {global_avg_latency:.2f} ns")

if __name__ == "__main__":
    main()
