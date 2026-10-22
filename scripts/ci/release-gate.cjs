const { execFileSync } = require('node:child_process');
const { mkdirSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const REQUIRED = Object.freeze(['build.yml', 'privileged-audit.yml', 'codeql.yml']);
const MAX_PAGES = 10;

async function discoverRuns(github, repo, sha, workflow, observations) {
  // GitHub's head_sha and event filters have returned empty lists even when
  // the exact successful main push exists (including CodeQL with event=push).
  // Read unfiltered workflow history and verify SHA, branch and event locally.
  for (let page = 1; page <= MAX_PAGES; page++) {
    const response = await github.rest.actions.listWorkflowRuns({
      ...repo, workflow_id: workflow,
      per_page: 100, page,
    });
    const runs = response.data?.workflow_runs;
    if (!Array.isArray(runs)) throw new Error(`${workflow} returned an invalid workflow_runs response`);
    observations.push({ workflow, page, count: runs.length, runs: runs.slice(0, 10).map(run => ({
      id: run.id, head_sha: run.head_sha, head_branch: run.head_branch,
      event: run.event, status: run.status, conclusion: run.conclusion,
    })) });
    const matches = runs.filter(run => run.head_sha === sha && run.head_branch === 'main' && run.event === 'push');
    if (matches.length || runs.length < 100) return matches;
  }
  throw new Error(`${workflow} has no matching main push in the latest ${MAX_PAGES * 100} workflow runs`);
}

function requireSuccessfulRun(runs, sha, workflow) {
  // Only a main push validates the actual released commit. PR merge refs and
  // successful runs for another SHA must never authorize a release.
  const candidates = runs.filter(run => run.head_sha === sha && run.head_branch === 'main' && run.event === 'push');
  candidates.sort((a, b) => b.id - a.id || b.run_attempt - a.run_attempt);
  const run = candidates[0];
  if (!run || run.status !== 'completed' || run.conclusion !== 'success') {
    throw new Error(`${workflow} must succeed on main at ${sha}; latest result: ${run ? `${run.status}/${run.conclusion} (${run.html_url})` : 'missing'}`);
  }
  return run;
}

async function releaseGate({ github, context, core, artifactDir = 'ci-artifacts' }) {
  let sha;
  const evidence = [];
  const observations = [];
  mkdirSync(artifactDir, { recursive: true });
  try {
    sha = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    if (sha !== context.sha) throw new Error(`checkout ${sha} differs from event ${context.sha}`);
    for (const workflow of REQUIRED) {
      const runs = await discoverRuns(github, context.repo, sha, workflow, observations);
      const run = requireSuccessfulRun(runs, sha, workflow);
      evidence.push(`- ${workflow}: ${run.html_url} (attempt ${run.run_attempt})`);
    }
    core.info(`Release gate passed for ${sha}\n${evidence.join('\n')}`);
    await core.summary.addHeading('Release CI gate').addRaw(`Commit: ${sha}\n\n${evidence.join('\n')}`).write();
    writeFileSync(join(artifactDir, 'release-gate.json'), JSON.stringify({ sha, evidence, observations, result: 'success' }, null, 2));
  } catch (error) {
    writeFileSync(join(artifactDir, 'release-gate.json'), JSON.stringify({ sha, evidence, observations, result: 'failure', error: error.message }, null, 2));
    throw error;
  }
}
module.exports = releaseGate;
module.exports.requireSuccessfulRun = requireSuccessfulRun;
module.exports.discoverRuns = discoverRuns;
module.exports.REQUIRED = REQUIRED;
