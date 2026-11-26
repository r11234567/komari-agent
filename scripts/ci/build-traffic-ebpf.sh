#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../internal/trafficwatch/ebpf"
clang=${CLANG:-clang-18}
includes="/usr/include/$(gcc -dumpmachine)"
for target in bpfel bpfeb; do
    "$clang" -target "$target" -g -O2 -Wall -Werror -I "$includes" \
        -fdebug-compilation-dir=. -c capture.c -o "capture_$target.o"
done
