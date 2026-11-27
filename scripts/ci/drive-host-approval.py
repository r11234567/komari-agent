"""Answer synthetic PAM prompts on the same OpenSSH terminal as the Host tool."""

from pathlib import Path
import sys

import pexpect


fixture = Path(sys.argv[1])
password = (fixture / "password").read_text().strip()
args = [
    "-tt", "-p", "22327", "-i", str(fixture / "client"),
    "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
    "-o", f"UserKnownHostsFile={fixture / 'known_hosts'}",
    "komari-stage6-admin@192.0.2.1",
]
with pexpect.spawn("/usr/bin/ssh", args, encoding="utf-8", echo=False, timeout=125) as child:
    mode, consent = "", ""
    while True:
        result = child.expect([
            r"HOST_PAM_FIXTURE (accept|deliberately-wrong) ([^\r\n]*)\r?\n",
            r"Legacy remote-control consent:",
            r"(?i)password:",
            pexpect.EOF,
        ])
        print(child.before.replace(password, "[redacted]"), end="", flush=True)
        if result == 0:
            mode, consent = child.match.groups()
        elif result == 1:
            assert consent, "unexpected consent prompt"
            child.sendline(consent)
        elif result == 2:
            assert mode, "unexpected PAM prompt"
            child.sendline(password if mode == "accept" else "wrong-fixture-password")
            mode = ""
        else:
            break
child.close()
sys.exit(child.exitstatus if child.exitstatus is not None else 1)
