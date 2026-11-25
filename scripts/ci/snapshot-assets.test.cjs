const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createHash, generateKeyPairSync, sign } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { basename, join } = require('node:path');
const { prepareSnapshotAssets, linuxArchitectures, windowsArchitectures } = require('./snapshot-assets.cjs');
const version = 'Snapshot-0000000000';
const fixtureKeys = new Map();
const prepareFixtureAssets = directory => prepareSnapshotAssets(directory, version, fixtureKeys.get(directory).publisher);

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'komari-synthetic-snapshot-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publisher = { algorithm: 'Ed25519', key_id: 'isolated-synthetic-publisher', public_key: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64') };
  fixtureKeys.set(directory, { publisher, privateKey });
  t.after(() => fixtureKeys.delete(directory));
  function addAsset(component, os, arch) {
    const name = `${component}-${os}-${arch}${os === 'windows' ? '.exe' : ''}`;
    const content = Buffer.from(`isolated synthetic artifact for ${name}`);
    const sha256 = createHash('sha256').update(content).digest('hex');
    writeFileSync(join(directory, name), content);
    writeFileSync(join(directory, name + '.sha256'), `${sha256}  ${name}\n`);
    const payload = Buffer.from(JSON.stringify({ schema: 'komari.release.v1', component, version, os, arch, sha256 }));
    writeFileSync(join(directory, name + '.release.json'), JSON.stringify({ payload: payload.toString('base64'), key_id: publisher.key_id, signature: sign(null, payload, privateKey).toString('base64') }));
  }
  for (const arch of linuxArchitectures) {
    for (const component of ['komari-agent', 'komari-host', 'komari-agent-rescue']) {
      addAsset(component, 'linux', arch);
    }
  }
  for (const arch of windowsArchitectures) {
    addAsset('komari-agent', 'windows', arch);
  }
  return directory;
}

test('publication inventory satisfies every Linux installer target and sha256sum', t => {
  const directory = fixture(t);
  writeFileSync(join(directory, 'komari-host-windows-amd64.exe'), 'synthetic out-of-scope Host asset');
  const paths = prepareFixtureAssets(directory);
  const names = paths.map(path => basename(path));
  for (const arch of linuxArchitectures) {
    for (const component of ['komari-agent', 'komari-host', 'komari-agent-rescue']) {
      assert.ok(names.includes(`${component}-linux-${arch}`));
      assert.ok(names.includes(`${component}-linux-${arch}.sha256`));
      assert.ok(names.includes(`${component}-linux-${arch}.release.json`));
    }
    assert.ok(names.includes(`komari-agent-rescue-linux-${arch}.release.json`));
  }
  assert.ok(names.includes('komari-agent-windows-amd64.exe'));
  assert.ok(names.includes('komari-agent-windows-amd64.exe.release.json'));
  assert.ok(!names.includes('komari-host-windows-amd64.exe'));
  assert.ok(names.includes('SHA256SUMS'));
  execFileSync('sha256sum', ['--check', 'SHA256SUMS'], { cwd: directory });
});

test('publication stops before release creation when any Linux Host asset is missing', t => {
  for (const arch of linuxArchitectures) {
    for (const suffix of ['', '.sha256']) {
      const directory = fixture(t);
      unlinkSync(join(directory, `komari-host-linux-${arch}${suffix}`));
      assert.throws(() => prepareFixtureAssets(directory), /Missing Linux installer asset/);
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
    assert.throws(() => prepareFixtureAssets(directory), /Checksum mismatch or invalid sidecar/);
  }
});

test('publication rejects missing, untrusted or wrongly bound rescue releases', t => {
  for (const kind of ['missing', 'signature', 'version', 'architecture', 'digest']) {
    const directory = fixture(t);
    const path = join(directory, 'komari-agent-rescue-linux-amd64.release.json');
    if (kind === 'missing') unlinkSync(path);
    else {
      const metadata = JSON.parse(readFileSync(path, 'utf8'));
      const payload = JSON.parse(Buffer.from(metadata.payload, 'base64').toString('utf8'));
      if (kind === 'version') payload.version = 'Snapshot-0000000001';
      if (kind === 'architecture') payload.arch = 'arm64';
      if (kind === 'digest') payload.sha256 = '0'.repeat(64);
      const bytes = Buffer.from(JSON.stringify(payload));
      metadata.payload = bytes.toString('base64');
      metadata.signature = (kind === 'signature' ? Buffer.alloc(64) : sign(null, bytes, fixtureKeys.get(directory).privateKey)).toString('base64');
      writeFileSync(path, JSON.stringify(metadata));
    }
    assert.throws(() => prepareFixtureAssets(directory), /Missing signed release metadata|Untrusted release signature|Release binding mismatch/);
  }
});

test('publication requires the Agent and Host signatures on supported installer targets', t => {
  for (const name of ['komari-agent-linux-amd64', 'komari-host-linux-arm64', 'komari-agent-windows-amd64.exe']) {
    const directory = fixture(t);
    unlinkSync(join(directory, name + '.release.json'));
    assert.throws(() => prepareFixtureAssets(directory), /Missing signed release metadata/);
  }
});
