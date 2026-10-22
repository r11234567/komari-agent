const { test } = require('node:test');
const assert = require('node:assert/strict');
const { requireSuccessfulRun } = require('./release-gate.cjs');
const releaseGate = require('./release-gate.cjs');
const { execFileSync } = require('node:child_process');
const { mkdtempSync, readFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

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
    github: { rest: { actions: {
      async listWorkflowRuns(query) {
        assert.equal(query.head_sha, undefined);
        assert.equal(query.event, 'push');
        assert.equal(query.branch, 'main');
        requests.push(query.workflow_id);
        return { data: { workflow_runs: [{ ...success, head_sha: sha }] } };
      },
    } } },
  };
  const evidence = () => JSON.parse(readFileSync(join(artifactDir, 'release-gate.json'), 'utf8'));
  try {
    await releaseGate(options);
    assert.deepEqual(requests, ['build.yml', 'privileged-audit.yml', 'codeql.yml']);
    assert.equal(evidence().result, 'success');
    assert.equal(evidence().evidence.length, 3);
    options.github.rest.actions.listWorkflowRuns = async () => { throw new Error('API unavailable'); };
    await assert.rejects(releaseGate(options), /API unavailable/);
    assert.equal(evidence().result, 'failure');
    assert.equal(evidence().error, 'API unavailable');
    await assert.rejects(releaseGate({ ...options, context: { ...options.context, sha: 'wrong-sha' } }), /differs from event/);
  } finally {
    rmSync(artifactDir, { recursive: true, force: true });
  }
});

test('release discovery pages main history without the unreliable SHA search filter', async () => {
  const sha = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  const artifactDir = mkdtempSync(join(tmpdir(), 'komari-release-discovery-'));
  const summary = { addHeading() { return this; }, addRaw() { return this; }, async write() {} };
  const requests = [];
  let results = [{ ...success, head_sha: sha }];
  const options = {
    artifactDir, context: { sha, repo: { owner: 'example', repo: 'agent' } },
    core: { info() {}, summary },
    github: { rest: { actions: { async listWorkflowRuns(query) {
      assert.equal(query.head_sha, undefined, 'must not use the empty SHA-filtered search');
      requests.push({ workflow: query.workflow_id, page: query.page });
      if (query.page === 1) return { data: { workflow_runs: Array.from({ length: 100 }, (_, id) => ({ ...success, id: id + 10, head_sha: 'newer-sha' })) } };
      return { data: { workflow_runs: results } };
    } } } },
  };
  const evidence = () => JSON.parse(readFileSync(join(artifactDir, 'release-gate.json'), 'utf8'));
  try {
    await releaseGate(options);
    assert.deepEqual(requests.map(r => r.page), [1, 2, 1, 2, 1, 2]);
    assert.equal(evidence().observations.length, 6);
    for (const invalid of [
      { head_sha: 'another-sha' }, { event: 'pull_request' }, { head_branch: 'feature' },
      { conclusion: 'failure' }, { status: 'in_progress', conclusion: null },
    ]) {
      results = [{ ...success, head_sha: sha, ...invalid }];
      await assert.rejects(releaseGate(options), /must succeed/);
      assert.equal(evidence().result, 'failure');
      assert.equal(evidence().observations.at(-1).runs[0].head_sha, results[0].head_sha);
    }
    options.github.rest.actions.listWorkflowRuns = async () => ({ data: {} });
    await assert.rejects(releaseGate(options), /invalid workflow_runs response/);
  } finally {
    rmSync(artifactDir, { recursive: true, force: true });
  }
});
