const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { basename, join } = require('node:path');
const { prepareSnapshotAssets, linuxArchitectures } = require('./snapshot-assets.cjs');

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'komari-synthetic-snapshot-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const arch of linuxArchitectures) {
    for (const component of ['komari-agent', 'komari-host']) {
      const name = `${component}-linux-${arch}`;
      const content = Buffer.from(`isolated synthetic artifact for ${name}`);
      writeFileSync(join(directory, name), content);
      writeFileSync(join(directory, `${name}.sha256`), `${createHash('sha256').update(content).digest('hex')}  ${name}\n`);
    }
  }
  return directory;
}

test('publication inventory satisfies every Linux installer target and sha256sum', t => {
  const directory = fixture(t);
  writeFileSync(join(directory, 'komari-agent-windows-amd64.exe'), 'synthetic existing Agent asset');
  writeFileSync(join(directory, 'komari-host-windows-amd64.exe'), 'synthetic out-of-scope Host asset');
  const paths = execFileSync(process.execPath, [join(__dirname, 'snapshot-assets.cjs'), directory], { encoding: 'utf8' }).trim().split('\n');
  const names = paths.map(path => basename(path));
  for (const arch of linuxArchitectures) {
    for (const component of ['komari-agent', 'komari-host']) {
      assert.ok(names.includes(`${component}-linux-${arch}`));
      assert.ok(names.includes(`${component}-linux-${arch}.sha256`));
    }
  }
  assert.ok(names.includes('komari-agent-windows-amd64.exe'));
  assert.ok(!names.includes('komari-host-windows-amd64.exe'));
  assert.ok(names.includes('SHA256SUMS'));
  execFileSync('sha256sum', ['--check', 'SHA256SUMS'], { cwd: directory });
});

test('publication stops before release creation when any Linux Host asset is missing', t => {
  for (const arch of linuxArchitectures) {
    for (const suffix of ['', '.sha256']) {
      const directory = fixture(t);
      unlinkSync(join(directory, `komari-host-linux-${arch}${suffix}`));
      assert.throws(() => prepareSnapshotAssets(directory), /Missing Linux installer asset/);
    }
  }
});

test('publication refuses altered binaries, invalid hashes and redirected checksum filenames', t => {
  for (const kind of ['binary', 'hash', 'filename']) {
    const directory = fixture(t);
    const name = 'komari-host-linux-amd64';
    const checksum = join(directory, `${name}.sha256`);
    if (kind === 'binary') writeFileSync(join(directory, name), 'changed synthetic bytes');
    if (kind === 'hash') writeFileSync(checksum, `invalid  ${name}\n`);
    if (kind === 'filename') writeFileSync(checksum, readFileSync(checksum, 'utf8').replace(name, '../other-file'));
    assert.throws(() => prepareSnapshotAssets(directory), /Checksum mismatch or invalid sidecar/);
  }
});
