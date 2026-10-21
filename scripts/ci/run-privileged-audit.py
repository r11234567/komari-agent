#!/usr/bin/env python3
"""Run the formerly failing audit scenarios as mandatory regression tests."""
import json, os, subprocess, sys
from pathlib import Path
root=Path(__file__).resolve().parents[2]
logs=root/'ci-artifacts';logs.mkdir(exist_ok=True)
command=['go','test','-p=2','-json','-count=1','-timeout=5m','-run=TestRegression|TestRequiredPrivilegeModeCannotBeDropped','./core/runtimeconfig','./core/privileged','./core/capability','./core/statelock']
with (logs/'audit.jsonl').open('w') as out,(logs/'audit-build.log').open('w') as err:
 result=subprocess.run(command,cwd=root,env=dict(os.environ,GOMAXPROCS='2'),stdout=out,stderr=err,timeout=600)
events=[]
for line in (logs/'audit.jsonl').read_text().splitlines():
 try: events.append(json.loads(line))
 except json.JSONDecodeError: pass
(logs/'audit.log').write_text(''.join(e.get('Output','') for e in events))
failed=[e.get('Test',e.get('Package')) for e in events if e.get('Action')=='fail']
passed={e['Test'] for e in events if e.get('Action')=='pass' and e.get('Test')}
required={'TestRegressionAppliedPrivilegeBlockedByInstallFlag','TestRegressionAppliedGPUNotUsedByCollectors','TestRegressionProtocolSettingsSilentlyIgnored','TestRegressionSecondRollbackCanWidenWithoutAuthentication','TestRegressionDaemonStoreOverwritesCLIChange','TestRegressionSeparateExecutionAndWebSSHFlagsIgnored'}
summary={'failures':failed,'passed':sorted(passed),'missing':sorted(required-passed),'exit_code':result.returncode}
(logs/'audit-inventory.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
if result.returncode or failed or required-passed or any(e.get('Action')=='skip' for e in events): sys.exit(1)
