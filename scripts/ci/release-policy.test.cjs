const { test } = require('node:test');
const assert = require('node:assert/strict');
const { MODULE, verifyProtocol } = require('./check-protocol.cjs');
const { requireSuccessfulRun } = require('./release-gate.cjs');
const releaseGate = require('./release-gate.cjs');
const { execFileSync } = require('node:child_process');
const { mkdtempSync, readFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const pin = version => ({ Require: [{ Path: MODULE, Version: version }] });
const resolved = version => ({ Path: MODULE, Version: version });
const sums = version => `${MODULE} ${version} h1:fixture\n${MODULE} ${version}/go.mod h1:fixture\n`;

test('protocol bumps need only a reviewed go.mod/go.sum update', () => {
  for (const version of ['v1.0.0', 'v1.1.0-0.20261022100337-b2ffe86ac2d6']) {
    assert.equal(verifyProtocol(pin(version), resolved(version), sums(version)), `${MODULE} ${version}`);
  }
});
test('protocol gate rejects stale resolution, replacements and missing checksums', () => {
  assert.throws(() => verifyProtocol(pin('v1.1.0'), resolved('v1.0.0'), sums('v1.1.0')), /differs from go.mod/);
  assert.throws(() => verifyProtocol({ ...pin('v1.0.0'), Replace: [{ Old: { Path: MODULE } }] }, resolved('v1.0.0'), sums('v1.0.0')), /replace/);
  assert.throws(() => verifyProtocol(pin('v1.0.0'), { ...resolved('v1.0.0'), Replace: {} }, sums('v1.0.0')), /replace/);
  assert.throws(() => verifyProtocol(pin('v1.0.0'), resolved('v1.0.0'), ''), /go.sum is missing/);
  assert.throws(() => verifyProtocol(pin('v1.0.0'), resolved('v1.0.0'), sums('v1.0.0').split('\n')[0]), /go.sum is missing/);
});

const success = { id: 1, run_attempt: 1, head_sha: 'exact-sha', head_branch: 'main', event: 'push', status: 'completed', conclusion: 'success', html_url: 'https://example.test/run/1' };
const check = runs => requireSuccessfulRun(runs, 'exact-sha', 'build.yml');
test('release requires successful main push checks for the exact SHA', () => {
  assert.equal(check([success]), success);
  for (const runs of [[], [{ ...success, head_sha: 'older-sha' }], [{ ...success, event: 'pull_request' }], [{ ...success, head_branch: 'feature' }]]) {
    assert.throws(() => check(runs), /missing/);
  }
});
test('release blocks failed, cancelled, skipped, pending and rerunning checks', () => {
  for (const conclusion of ['failure', 'cancelled', 'skipped', 'timed_out', 'action_required', null]) {
    assert.throws(() => check([{ ...success, conclusion }]), /must succeed/);
  }
  for (const status of ['queued', 'in_progress']) {
    assert.throws(() => check([{ ...success, status }]), /must succeed/);
  }
  assert.throws(() => check([success, { ...success, id: 2, conclusion: 'failure' }]), /must succeed/);
  assert.throws(() => check([success, { ...success, run_attempt: 2, status: 'in_progress', conclusion: null }]), /must succeed/);
});

test('release checks all required workflows and retains API failures as evidence', async () => {
  const sha = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  const artifactDir = mkdtempSync(join(tmpdir(), 'komari-release-gate-'));
  const requests = [];
  const summary = { addHeading() { return this; }, addRaw() { return this; }, async write() {} };
  const options = {
    artifactDir, context: { sha, repo: { owner: 'example', repo: 'agent' } },
    core: { info() {}, summary },
    github: {
      rest: { actions: { listWorkflowRuns: 'workflow-api' } },
      async paginate(route, query) {
        assert.equal(route, 'workflow-api');
        assert.equal(query.head_sha, sha);
        assert.equal(query.event, 'push');
        assert.equal(query.branch, 'main');
        requests.push(query.workflow_id);
        return [{ ...success, head_sha: sha }];
      },
    },
  };
  const evidence = () => JSON.parse(readFileSync(join(artifactDir, 'release-gate.json'), 'utf8'));
  try {
    await releaseGate(options);
    assert.deepEqual(requests, ['build.yml', 'privileged-audit.yml', 'codeql.yml']);
    assert.equal(evidence().result, 'success');
    assert.equal(evidence().evidence.length, 3);
    options.github.paginate = async () => { throw new Error('API unavailable'); };
    await assert.rejects(releaseGate(options), /API unavailable/);
    assert.equal(evidence().result, 'failure');
    assert.equal(evidence().error, 'API unavailable');
    await assert.rejects(releaseGate({ ...options, context: { ...options.context, sha: 'wrong-sha' } }), /differs from event/);
  } finally {
    rmSync(artifactDir, { recursive: true, force: true });
  }
});
