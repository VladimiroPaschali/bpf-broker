# ebpf-pubsub

The research project aims to explore how efficient eBPF can accelerate pub-sub systems.

## Tested Environment

All experiments and development were run on the following environment:

- OS: Ubuntu 24.04
- Kernel: Linux version 6.8.x

## Project Dependencies Setup

The following tools and libraries are required:

- `gpg`
- `curl`
- `tar`
- `xz-utils`
- `make`
- `gcc`
- `flex`
- `bison`
- `libssl-dev`
- `libelf-dev`
- `llvm`
- `clang`

## Installation (Ubuntu/Debian)

Run the following command to install all required dependencies:

```bash
$ sudo apt update && sudo apt install -y \
  gpg curl tar xz-utils make gcc flex bison \
  libssl-dev libelf-dev \
  llvm clang
```

## Build 
```bash
$ ./kernel-src-download.sh
$ ./kernel-src-prepare.sh
$ cd bmc 
$ chmod +x ./setup-bpf-headers.sh
$ ./setup-bpf-headers.sh
$ make
```
