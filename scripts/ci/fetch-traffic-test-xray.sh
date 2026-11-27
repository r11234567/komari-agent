#!/usr/bin/env bash
set -euo pipefail

dest=${1:?provide a temporary test tools directory}
mkdir -p "$dest"
cd "$dest"
curl --fail --location --silent --show-error --max-time 90 -o Xray-linux-64.zip \
  https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-64.zip
printf '%s  Xray-linux-64.zip\n' e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214 | sha256sum --check
unzip -o Xray-linux-64.zip xray
