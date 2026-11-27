#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
dir=$root/fixtures/ubuntu
mkdir -p "$dir"
cd "$dir"
base=https://cloud-images.ubuntu.com/noble/current
for file in SHA256SUMS SHA256SUMS.gpg; do
    curl --fail --silent --show-error --location --retry 2 --output "$file" "$base/$file"
done
gpgv --keyring /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg SHA256SUMS.gpg SHA256SUMS
image=noble-server-cloudimg-amd64.img
awk -v image="$image" '$2 == "*" image || $2 == image {print}' SHA256SUMS > image.sha256
test -s image.sha256
if ! sha256sum --check image.sha256; then
    curl --fail --silent --show-error --location --retry 2 --output "$image" "$base/$image"
    sha256sum --check image.sha256
fi
