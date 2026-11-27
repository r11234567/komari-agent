#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")" && pwd)
image_dir=$repo/fixtures/ubuntu
image=$image_dir/noble-server-cloudimg-amd64.img
(cd "$image_dir" && sha256sum --check image.sha256)
work=$(mktemp -d /tmp/komari-vm-check.XXXXXX)
chmod 0700 "$work"
vm_pid=
cleanup() {
    if [[ -n "$vm_pid" ]]; then
        kill "$vm_pid" 2>/dev/null || true
        wait "$vm_pid" 2>/dev/null || true
    fi
    rm -f "$work/guest.qcow2" "$work/seed.iso" "$work/kit.iso" "$work/user-data" "$work/meta-data" "$work/guest.sock" "$work/records.sock" "$work/console.log" "$work/panel.pem" "$work/kit/collector" "$work/kit/"*.deb
    rmdir "$work/kit"
    rmdir "$work"
}
trap cleanup EXIT
cd "$repo"
mkdir "$work/kit"
CGO_ENABLED=0 go build -buildvcs=false -trimpath -o "$work/kit/collector" ./cmd/test-collector
(cd "$work/kit" && apt-get download qemu-guest-agent liburing2)
genisoimage -quiet -J -R -V komari-qga-kit -o "$work/kit.iso" "$work/kit"
openssl genpkey -algorithm X25519 -out "$work/panel.pem"
public=$(openssl pkey -in "$work/panel.pem" -pubout -outform DER | tail -c 32 | base64 -w0)
private=$(openssl pkey -in "$work/panel.pem" -outform DER | tail -c 32 | base64 -w0)
fixture_a=$(openssl rand -hex 32)
fixture_b=$(openssl rand -hex 32)
fixture_c=$(openssl rand -hex 32)
unread_fixture=$(openssl rand -hex 32)
fixture=$(printf '%s\n%s\n%s' "$fixture_a" "$fixture_b" "$fixture_c")
cat > "$work/user-data" <<CLOUD
#cloud-config
write_files:
  - path: /run/komari-fixture/account-01
    permissions: '0600'
    content: "$fixture_a\n"
  - path: /run/komari-fixture/account-02
    permissions: '0600'
    content: "$fixture_b\n"
  - path: /run/komari-fixture/account-03
    permissions: '0600'
    content: "$fixture_c\n"
  - path: /run/komari-fixture/never-requested
    permissions: '0600'
    content: "$unread_fixture\n"
runcmd:
  - [install, -d, -m, '0700', /run/komari-qga-kit]
  - [mount, -o, ro, /dev/disk/by-label/komari-qga-kit, /run/komari-qga-kit]
  - [sh, -ec, 'dpkg -i /run/komari-qga-kit/liburing2_*.deb /run/komari-qga-kit/qemu-guest-agent_*.deb']
  - [install, -m, '0700', /run/komari-qga-kit/collector, /usr/local/bin/komari-test-collector]
  - [systemctl, start, qemu-guest-agent.service]
  - [systemd-run, --unit=komari-fixture-collector, --property=StandardError=journal+console, /usr/local/bin/komari-test-collector, "$public"]
CLOUD
printf 'instance-id: komari-local-verification\nlocal-hostname: komari-local-verification\n' > "$work/meta-data"
cloud-localds "$work/seed.iso" "$work/user-data" "$work/meta-data"
qemu-img create -q -f qcow2 -F qcow2 -b "$image" "$work/guest.qcow2"
qemu-system-x86_64 -machine q35 -accel kvm -accel tcg,thread=multi -m 1024 -smp 2 \
    -nodefaults -display none -serial "file:$work/console.log" -no-reboot \
    -drive "file=$work/guest.qcow2,if=virtio,format=qcow2" -drive "file=$work/seed.iso,if=virtio,format=raw,readonly=on" \
    -drive "file=$work/kit.iso,if=virtio,format=raw,readonly=on" \
    -netdev user,id=eth0,restrict=on -device virtio-net-pci,netdev=eth0 \
    -device virtio-serial-pci -chardev "socket,id=guestagent,path=$work/guest.sock,server=on,wait=off" \
    -device virtserialport,chardev=guestagent,name=org.qemu.guest_agent.0 \
    -chardev "socket,id=records,path=$work/records.sock,server=on,wait=off" \
    -device virtserialport,chardev=records,name=org.komari.test.records &
vm_pid=$!
cd "$repo"
if ! KOMARI_TEST_VM_SOCKET="$work/guest.sock" KOMARI_TEST_RECORDS_SOCKET="$work/records.sock" \
    KOMARI_TEST_PANEL_KEY="$private" KOMARI_TEST_FIXTURE_VALUE="$fixture" KOMARI_TEST_UNREAD_VALUE="$unread_fixture" \
    go test ./qgatest -run TestRealGuestTransport -count=1 -timeout 9m -v; then
    tail -n 70 "$work/console.log" || true
    exit 1
fi
