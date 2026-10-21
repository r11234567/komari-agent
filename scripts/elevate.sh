#!/bin/sh
# Retired: a daemon-writable script cannot be a privileged management entrypoint.
echo 'Legacy elevation is disabled. Use the root-owned komari-host tool; migrate the installation first.' >&2
exit 1
