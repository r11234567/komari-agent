#!/usr/bin/env python3
"""Track desired invariants without silently accepting new failures.

Known failures are explicit debt for stages 3–6. A new failure, build error,
missing test, unexpected skip OR unexpected pass fails the audit inventory job.
All fixture state is temporary; system/auth commands are mocked.
"""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
logs = root / 'ci-artifacts'
logs.mkdir(exist_ok=True)
fixture = root / 'tests/privileged-audit'
mapping = {
 'core/runtimeconfig/audit_probe_test.go': 'runtime_probe_test.go.txt',
 'core/privileged/audit_probe_test.go': 'store_probe_test.go.txt',
 'core/capability/audit_probe_test.go': 'capability_probe_test.go.txt',
 'cmd/audit_probe_test.go': 'cmd_probe_test.go.txt',
}
expected = {
 'TestAuditAppliedPrivilegeBlockedByInstallFlag', 'TestAuditAppliedGPUNotUsedByCollectors',
 'TestAuditProtocolSettingsSilentlyIgnored', 'TestAuditRequiredPrivilegeModeIsLost',
 'TestAuditSecondRollbackCanWidenWithoutAuthentication', 'TestAuditDaemonStoreOverwritesCLIChange',
 'TestAuditSeparateExecutionAndWebSSHFlagsIgnored', 'TestAuditManualOutcomeDeliveredBeforeNonceValidation',
 'TestAuditCustomServiceNameNotPassedToElevation',
}
root_test = 'TestAuditSudoCLISkipsDaemonElevation'
env = dict(os.environ, GOMAXPROCS='2')
with tempfile.TemporaryDirectory(prefix='komari-audit-') as temp:
 overlay = Path(temp) / 'overlay.json'
 overlay.write_text(json.dumps({'Replace': {str(root/k): str(fixture/v) for k,v in mapping.items()}}, indent=2))
 command = ['go', 'test', '-p=2', '-overlay', str(overlay), '-json', '-count=1', '-timeout=5m', '-run=^TestAudit', './cmd', './core/runtimeconfig', './core/privileged', './core/capability']
 with (logs/'audit.jsonl').open('w') as out, (logs/'audit-build.log').open('w') as err:
  result = subprocess.run(command, cwd=root, env=env, stdout=out, stderr=err, timeout=600)
 events=[]
 for line in (logs/'audit.jsonl').read_text().splitlines():
  try: events.append(json.loads(line))
  except json.JSONDecodeError: pass
 (logs/'audit.log').write_text(''.join(e.get('Output','') for e in events))
 failed={e['Test'] for e in events if e.get('Action')=='fail' and e.get('Test')}
 passed={e['Test'] for e in events if e.get('Action')=='pass' and e.get('Test')}
 skipped={e['Test'] for e in events if e.get('Action')=='skip' and e.get('Test')}
 summary={'known_unfixed_invariants': sorted(failed), 'unexpected_failures':sorted(failed-expected), 'unexpected_passes':sorted(passed), 'missing_failures':sorted(expected-failed), 'skipped':sorted(skipped), 'go_exit_code':result.returncode}
 (logs/'audit-inventory.json').write_text(json.dumps(summary,indent=2)+'\n')
 print(json.dumps(summary,indent=2),flush=True)
 if failed!=expected or passed or skipped!={root_test} or result.returncode!=1:
  sys.exit('Audit inventory changed or failed to build; inspect full artifacts and update debt deliberately.')
 for name in sorted(failed): print('::warning title=Known agent defect::'+name,flush=True)
 # Compile as the normal user; run only the isolated root/PTY probe as root.
 binary=Path(temp)/'rootprobe.test'
 with (logs/'root-build.log').open('w') as out:
  built=subprocess.run(['go','test','-p=2','-overlay',str(overlay),'-c','-o',str(binary),'./cmd'],cwd=root,env=env,stdout=out,stderr=subprocess.STDOUT,timeout=600)
 if built.returncode:sys.exit('Root probe did not build; see root-build.log')
 rootcmd=shlex.join(['sudo','-n',str(binary),'-test.run=^'+root_test+'$','-test.v','-test.timeout=30s'])
 with (logs/'root-pty.log').open('w') as out:
  ran=subprocess.run(['script','-q','-e','-c',rootcmd,'/dev/null'],cwd=root,stdout=out,stderr=subprocess.STDOUT,timeout=60)
 output=(logs/'root-pty.log').read_text()
 if ran.returncode!=1 or ('--- FAIL: '+root_test) not in output or '--- SKIP:' in output:
  sys.exit('Root/PTY probe changed or failed before its assertion; inspect root-pty.log')
 print('::warning title=Known agent defect::'+root_test,flush=True)
 print('Known-defect inventory matches. These invariants remain unfixed; this is not a passing security regression suite.')
