const { execFileSync } = require('node:child_process');
const { mkdirSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const REQUIRED = ['build.yml', 'privileged-audit.yml', 'codeql.yml'];

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
  mkdirSync(artifactDir, { recursive: true });
  try {
    sha = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    if (sha !== context.sha) throw new Error(`checkout ${sha} differs from event ${context.sha}`);
    for (const workflow of REQUIRED) {
      const runs = await github.paginate(github.rest.actions.listWorkflowRuns, {
        ...context.repo, workflow_id: workflow, head_sha: sha,
        branch: 'main', event: 'push', per_page: 100,
      });
      const run = requireSuccessfulRun(runs, sha, workflow);
      evidence.push(`- ${workflow}: ${run.html_url} (attempt ${run.run_attempt})`);
    }
    core.info(`Release gate passed for ${sha}\n${evidence.join('\n')}`);
    await core.summary.addHeading('Release CI gate').addRaw(`Commit: ${sha}\n\n${evidence.join('\n')}`).write();
    writeFileSync(join(artifactDir, 'release-gate.json'), JSON.stringify({ sha, evidence, result: 'success' }, null, 2));
  } catch (error) {
    writeFileSync(join(artifactDir, 'release-gate.json'), JSON.stringify({ sha, evidence, result: 'failure', error: error.message }, null, 2));
    throw error;
  }
}
module.exports = releaseGate;
module.exports.requireSuccessfulRun = requireSuccessfulRun;
