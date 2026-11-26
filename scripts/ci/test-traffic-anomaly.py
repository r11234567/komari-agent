#!/usr/bin/env python3
"""Exercise the actual Agent, nfpcapd, nfdump and Xray on isolated veth links."""

import contextlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def retry(fn, seconds=120):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = fn()
        if result:
            return result
        time.sleep(1)
    raise AssertionError(f"timed out: {fn.__name__}")


def main(binary, xray, inbox=None):
    release = Path("/etc/os-release").read_text().splitlines()
    print(next((line for line in release if line.startswith("PRETTY_NAME=")), release[0]), flush=True)
    run("uname", "-r")
    run("nfpcapd", "-V")
    run("nfdump", "-V")
    suffix = uuid.uuid4().hex[:8]
    node, client, target = [f"traffic-{name}-{suffix}" for name in ("node", "client", "target")]
    with tempfile.TemporaryDirectory(prefix="komari-traffic-e2e-") as directory, contextlib.ExitStack() as cleanup:
        root = Path(directory)
        jobs = []

        def check_cleanup():
            for process in reversed(jobs):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)

        def start(namespace, name, *args, env=None):
            with (root / f"{name}.log").open("w") as log:
                process = subprocess.Popen(("ip", "netns", "exec", namespace, *args),
                                           stdout=log, stderr=log, env=env)
            jobs.append(process)
            return process

        for ns in (node, client, target):
            run("ip", "netns", "add", ns)
            cleanup.callback(run, "ip", "netns", "del", ns)
            run("ip", "-n", ns, "link", "set", "lo", "up")

        def link(node_link, peer, peer_link, ranges):
            left, right = f"l{suffix}{node_link[-1]}", f"r{suffix}{node_link[-1]}"
            run("ip", "link", "add", left, "netns", node, "type", "veth", "peer", "name", right, "netns", peer)
            for ns, old, name, index in ((node, left, node_link, 0), (peer, right, peer_link, 1)):
                run("ip", "-n", ns, "link", "set", old, "name", name)
                run("ip", "-n", ns, "link", "set", name, "up")
                for pair in ranges:
                    cmd = ("ip", "-n", ns, "addr", "add", pair[index], "dev", name)
                    run(*cmd, *("nodad",) if ":" in pair[index] else ())

        link("edge0", client, "peer0", [
            ("192.0.2.1/24", "192.0.2.2/24"), ("2001:db8:1::1/64", "2001:db8:1::2/64"),
        ])
        link("path1", target, "peer1", [("198.51.100.1/24", "198.51.100.2/24")])
        scratch = root / "scratch"
        scratch.mkdir(mode=0o700)
        run("mount", "-t", "tmpfs", "-o", "noswap,size=32M,mode=0700", "tmpfs", str(scratch))
        cleanup.callback(run, "umount", str(scratch))
        cleanup.callback(check_cleanup)

        policy = root / "xray.json"
        policy.write_text(json.dumps({
            "log": {"loglevel": "warning"},
            "api": {"tag": "api", "listen": "127.0.0.1:10085", "services": ["StatsService"]},
            "inbounds": [{"tag": "client", "listen": "192.0.2.1", "port": 11080, "protocol": "socks",
                          "settings": {"auth": "noauth"}}],
            "outbounds": [{"tag": "remote", "protocol": "freedom"}],
            "stats": {},
            "policy": {"system": {f"stats{side}{direction}": True
                                  for side in ("Inbound", "Outbound")
                                  for direction in ("Uplink", "Downlink")}},
        }))
        run("ip", "netns", "exec", node, xray, "run", "-test", "-c", str(policy))
        proxy = start(node, "xray", xray, "run", "-c", str(policy))
        (root / "test.bin").write_bytes(b"x" * (8 << 20))
        http = start(target, "http", sys.executable, "-u", "-m", "http.server", "10080",
                     "--bind", "198.51.100.2", "--directory", str(root))
        (root / "xray").symlink_to(xray)
        env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}"}
        url = "http://198.51.100.2:10080/test.bin"
        stat_args = ("ip", "netns", "exec", node, xray, "api", "stats", "-server=127.0.0.1:10085",
                     "-name=inbound>>>client>>>traffic>>>downlink", "-reset=false")
        socks = ("--socks5", "192.0.2.1:11080")

        def ready(namespace, *route):
            assert http.poll() is None, "HTTP fixture exited before becoming ready"
            assert proxy.poll() is None, "Xray exited before becoming ready"
            return subprocess.run(
                ("ip", "netns", "exec", namespace, "curl", "--noproxy", "", "--fail",
                 "--silent", "--head", "--connect-timeout", "1", "--max-time", "2", *route, url),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ).returncode == 0

        def launch(name, with_xray):
            state = root / name
            expired = state / f"event-{uuid.uuid4()}.json"
            state.mkdir(mode=0o700)
            expired.write_text('{"expires_at":"2000-01-01T00:00:00Z"}')
            cfg = {
                "interface": "edge0",
                "local_addresses": ["192.0.2.1", "2001:db8:1::1"],
                "scratch_dir": str(scratch),
                "state_dir": str(state),
                "thresholds": {"fast_bytes": 300_000, "slow_bytes": 30_000_000, "sustained_bytes": 30_000_000},
            }
            if with_xray:
                cfg["xray"] = {"endpoint": "127.0.0.1:10085", "policy_file": str(policy),
                               "inbound_tags": ["client"], "outbound_tags": ["remote"], "public_legs": "inbound"}
                if inbox is not None:
                    cfg["upload_dir"] = str(inbox)
            config = root / f"{name}.json"
            config.write_text(json.dumps(cfg))
            process = start(node, name, binary, "traffic-anomaly", "--config-file", str(config), env=env)

            def online():
                assert process.poll() is None, (root / f"{name}.log").read_text()
                return not expired.exists() and "nfpcapd" in (root / f"{name}.log").read_text()

            retry(online, 20)
            return process, state

        def stop(process):
            process.terminate()
            assert process.wait(timeout=30) == 0

        def snapshot(state):
            rows = list(state.glob("event-*.json"))
            return json.loads(rows[0].read_text()) if rows else None

        wait_for_boundary = lambda: time.sleep(32 - time.time() % 30)
        try:
            # Probe only with HEAD before capture; the measured GET gets one attempt.
            retry(lambda: ready(node), 20)
            retry(lambda: ready(client, *socks), 20)
            starting_bytes = int(json.loads(run(*stat_args, capture_output=True).stdout)["stat"]["value"])
            process, state = launch("ingress", True)
            wait_for_boundary()
            run("ip", "netns", "exec", client, "curl", "--noproxy", "", "--fail", "--silent", "--show-error",
                "--max-time", "15", *socks, "--output", "/dev/null", url)
            value = json.loads(run(*stat_args, capture_output=True).stdout)["stat"]["value"]
            assert int(value) - starting_bytes >= 8 << 20
            # Allow the entire two-minute detector window to cover the healthy
            # single-public-leg transfer before injecting unexplained traffic.
            time.sleep(175)
            assert snapshot(state) is None, "normal Xray transfer generated IP evidence"
            assert json.loads(run(*stat_args, capture_output=True).stdout)["stat"]["value"] == value

            udp = (
                "import socket,sys,time; addr=sys.argv[1]; "
                "s=socket.socket(socket.AF_INET6 if ':' in addr else socket.AF_INET,socket.SOCK_DGRAM); "
                "p=b'x'*1000; "
                "[(s.sendto(p,(addr,19999)),time.sleep(0.0005)) for _ in range(1500)]"
            )
            for address in ("192.0.2.1", "2001:db8:1::1"):
                run("ip", "netns", "exec", client, sys.executable, "-c", udp, address)
            assert snapshot(state) is None, "incident was saved before the short burst ended"
            def both_sources():
                event = snapshot(state)
                if event is not None:
                    sources = {item["ip"]: item["bytes"] for item in event["ingress_sources"]}
                    if all(sources.get(addr, 0) >= 1_500_000 for addr in ("192.0.2.2", "2001:db8:1::2")):
                        return event
                return None

            incoming = retry(both_sources, 130)
            assert incoming["reason"] == "fast_unexplained_ingress", incoming
            sources = {item["ip"]: item["bytes"] for item in incoming["ingress_sources"]}
            for address in ("192.0.2.2", "2001:db8:1::2"):
                assert 1_500_000 <= sources.get(address, 0) <= 1_650_000, incoming
            stop(process)
            hours = [json.loads(path.read_text()) for path in state.glob("hour-*.json")]
            assert sum(hour["services"].get("xray", {}).get("tx_bytes", 0) for hour in hours) >= 8 << 20, hours
            assert sum(hour["observed"]["tx_bytes"] for hour in hours) >= 8 << 20, hours
            assert all("192.0.2.2" not in json.dumps(hour) for hour in hours)
            assert not list(scratch.glob("flow-run-*")), "normal temporary files remained after shutdown"
            print("PASS: real Xray, split inbound and outbound links, non-resetting stats, and short IPv4/IPv6 bursts retained")
            print(f"  Xray downlink={value} bytes, ingress sources={sources}")

            process, state = launch("egress", False)
            time.sleep(123)
            sink_code = """
import socket
with socket.socket() as listener:
    listener.bind(('192.0.2.2', 19191))
    listener.listen()
    print('ready', flush=True)
    stream, _ = listener.accept()
    with stream:
        while stream.recv(65536):
            pass
"""
            sink = start(client, "sink", sys.executable, "-c", sink_code)

            def sink_ready():
                assert sink.poll() is None, (root / "sink.log").read_text()
                return "ready" in (root / "sink.log").read_text()

            retry(sink_ready, 10)
            talk = ("import socket,time; s=socket.create_connection(('192.0.2.2',19191)); "
                    "p=b'x'*16384; [(s.sendall(p),time.sleep(.15)) for _ in range(1200)]")
            sender = start(node, "sender", sys.executable, "-c", talk)

            def active_snapshot():
                assert sender.poll() is None, (root / "sender.log").read_text()
                return snapshot(state)

            outgoing = retry(active_snapshot, 150)
            assert outgoing["reason"] == "fast_unexplained_egress", outgoing
            assert any(p["ip"] == "192.0.2.2" and p["bytes"] > 300_000 for p in outgoing["egress_destinations"])
            stop(process)
            print("PASS: real active TCP egress exported before connection close, with destination and byte count")
            print(f"  egress destinations={outgoing['egress_destinations']}")
        except BaseException:
            for log in root.glob("*.log"):
                print(f"--- {log.name} ---\n{log.read_text()[-5000:]}", file=sys.stderr)
            raise


if __name__ == "__main__":
    main(str(Path(sys.argv[1]).resolve()), str(Path(sys.argv[2]).resolve()),
         Path(sys.argv[3]).resolve() if len(sys.argv) > 3 else None)
