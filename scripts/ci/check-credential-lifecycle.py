import json
from pathlib import Path
root=Path('ci-artifacts')
required={
 'TestCredentialRefreshPendingSurvivesReopenAndCommitFailure',
 'TestCredentialFileWatchAtomicRenameAndCancellation',
 'TestCredentialRefreshV2RejectsTamperingAndMissingProof',
 'TestCredentialRenewalOneOwnerForConcurrentCallers',
 'TestCredentialRenewalTimerRefreshesBeforeExpiryAndCancels',
 'TestDPoP_AutoRefreshOn401',
}
events=[json.loads(s) for s in (root/'credential-agent-go/tests.jsonl').read_text().splitlines() if s.strip()]
assert not any(e.get('Action')=='fail' for e in events), 'unit/package test failure'
passed={e.get('Test') for e in events if e.get('Action')=='pass'}
assert required <= passed, sorted(required-passed)
assert not any(e.get('Action')=='skip' and e.get('Test') in required for e in events), 'required test skipped'
name='TestCredentialHandoffPreservesFreshLeaseAndHonorsRevocation'
log=(root/'credential-handoff.log').read_text()
assert '--- PASS: '+name in log and '--- SKIP: '+name not in log and '--- FAIL:' not in log
for label in ('credential-agent','credential-handoff-build','credential-handoff'):
 assert (root/(label+'-exit-code.txt')).read_text().strip()=='0',label
(root/'credential-agent-evidence.json').write_text(json.dumps({'unit_assertions':sorted(required),'protected_handoff':name},indent=2)+'\n')
print('Observed required tests:',sorted(required),name)
