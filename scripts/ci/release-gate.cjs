const { execFileSync } = require('node:child_process');
const { mkdirSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const REQUIRED = Object.freeze(['build.yml', 'privileged-audit.yml', 'codeql.yml']);
const MAX_PAGES = 10;

function matchesRun(run, sha, dev = false) {
  return run.head_sha === sha && ((run.head_branch === 'main' && run.event === 'push') || (dev && run.event === 'pull_request'));
}

async function discoverRuns(github, repo, sha, workflow, observations, dev = false) {
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
    const matches = runs.filter(run => matchesRun(run, sha, dev));
    if (matches.length || runs.length < 100) return matches;
  }
  throw new Error(`${workflow} has no matching main push in the latest ${MAX_PAGES * 100} workflow runs`);
}

function requireSuccessfulRun(runs, sha, workflow, dev = false) {
  // Stable releases require a main push. An explicitly dev-tagged prerelease
  // may use PR evidence, but its recorded head SHA must still match exactly.
  const candidates = runs.filter(run => matchesRun(run, sha, dev));
  candidates.sort((a, b) => b.id - a.id || b.run_attempt - a.run_attempt);
  const run = candidates[0];
  if (!run || run.status !== 'completed' || run.conclusion !== 'success') {
    const error = new Error(`${workflow} must succeed ${dev ? 'on a pull request or main' : 'on main'} at ${sha}; latest result: ${run ? `${run.status}/${run.conclusion} (${run.html_url})` : 'missing'}`);
    error.retryable = !run || run.status === 'queued' || run.status === 'in_progress' || run.status === 'waiting' || run.status === 'requested' || run.status === 'pending';
    throw error;
  }
  return run;
}

async function releaseGate({ github, context, core, artifactDir = 'ci-artifacts' }) {
  let sha;
  const evidence = [];
  const observations = [];
  const release = context.payload?.release;
  const dev = context.eventName === 'release' && release?.prerelease === true && /^\d+\.\d+\.\d+-dev\.\d{8}\.\d+$/.test(release.tag_name);
  mkdirSync(artifactDir, { recursive: true });
  try {
    sha = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    if (sha !== context.sha) throw new Error(`checkout ${sha} differs from event ${context.sha}`);
    for (const workflow of REQUIRED) {
      const runs = await discoverRuns(github, context.repo, sha, workflow, observations, dev);
      const run = requireSuccessfulRun(runs, sha, workflow, dev);
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
