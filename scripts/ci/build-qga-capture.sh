#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../internal/qgastream/bpf"
for endian in bpfel bpfeb; do
    clang-18 -target "$endian" -I "/usr/include/$(gcc -dumpmachine)" -g -O2 -Wall -Werror \
        -fdebug-compilation-dir=. -c channel.c -o "channel_$endian.o"
done
