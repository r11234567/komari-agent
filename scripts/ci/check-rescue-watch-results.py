#!/usr/bin/env python3
"""Reject absent, skipped, or failed production-client watch regressions."""
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
required = {
    "TestRescueAuthorizationWatchSurvivesThirtySeconds",
    "TestRescueAuthorizationWatchTransportBoundsAndRedirects",
    "TestRescueAuthorizationWatchContextCancelsStalledHeaders",
    "TestRescueHeartbeatRejectsReplayDelayRegressionAndTampering",
    "TestRescueReceivesRealSignedStreamAndReportsDisconnect",
    "TestIdleManagedHelperCannotLeaseOrExecute",
}
passed, rejected = set(), []
for line in (root / "tests.jsonl").read_text().splitlines():
    event = json.loads(line)
    if event.get("Action") == "fail" or (
        event.get("Test") in required and event.get("Action") == "skip"
    ):
        rejected.append(event)
    if event.get("Package") == "github.com/komari-monitor/komari-agent/rescue" and event.get("Action") == "pass" and event.get("Test") in required:
        passed.add(event["Test"])
result = {"passed": sorted(passed), "missing": sorted(required - passed), "rejected": rejected}
(root / "required-evidence.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
if result["missing"] or rejected:
    raise SystemExit("Required rescue stream tests did not actually pass")
