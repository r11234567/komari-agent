const { createHash, createPublicKey, verify } = require('node:crypto');
const { lstatSync, readFileSync, readdirSync, writeFileSync } = require('node:fs');
const { join, resolve } = require('node:path');

const linuxArchitectures = ['386', 'amd64', 'arm', 'arm64', 'loong64'];
const digest = data => createHash('sha256').update(data).digest('hex');

// The Linux installer requires both components and their individual checksums
// from one tag, even for an update or a metrics-only installation.
function prepareSnapshotAssets(directory, version, publisher = JSON.parse(readFileSync(resolve(__dirname, '../../docs/release-signing-key.json'), 'utf8'))) {
  if (!/^Snapshot-\d{10}$/.test(version || '')) throw new Error('An exact Snapshot version is required');
  const names = readdirSync(directory);
  const required = linuxArchitectures.flatMap(arch =>
    ['komari-agent', 'komari-host', 'komari-agent-rescue'].map(component => `${component}-linux-${arch}`));
  for (const name of required) {
    for (const file of [name, `${name}.sha256`]) {
      if (!names.includes(file)) throw new Error(`Missing Linux installer asset: ${file}`);
      const stat = lstatSync(join(directory, file));
      if (!stat.isFile() || stat.size === 0) throw new Error(`Invalid Linux installer asset: ${file}`);
    }
    const checksum = readFileSync(join(directory, `${name}.sha256`), 'utf8').trim();
    const match = /^([a-fA-F0-9]{64})\s+\*?(\S+)$/.exec(checksum);
    if (!match || match[2] !== name || match[1].toLowerCase() !== digest(readFileSync(join(directory, name)))) {
      throw new Error(`Checksum mismatch or invalid sidecar: ${name}.sha256`);
    }
  }
  if (publisher.algorithm !== 'Ed25519') throw new Error('Invalid publisher algorithm');
  const rawKey = Buffer.from(publisher.public_key, 'base64');
  if (rawKey.length !== 32) throw new Error('Invalid publisher public key');
  const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), rawKey]), format: 'der', type: 'spki' });
  for (const arch of linuxArchitectures) {
    const name = `komari-agent-rescue-linux-${arch}`;
    const file = join(directory, `${name}.release.json`);
    if (!names.includes(`${name}.release.json`) || !lstatSync(file).isFile()) throw new Error(`Missing signed rescue metadata: ${name}`);
    const signed = JSON.parse(readFileSync(file, 'utf8'));
    const payload = Buffer.from(signed.payload, 'base64');
    if (signed.key_id !== publisher.key_id || !verify(null, payload, key, Buffer.from(signed.signature, 'base64'))) throw new Error(`Untrusted rescue signature: ${name}`);
    const metadata = JSON.parse(payload.toString('utf8'));
    if (metadata.schema !== 'komari.release.v1' || metadata.component !== 'komari-agent-rescue' || metadata.version !== version || metadata.os !== 'linux' || metadata.arch !== arch || metadata.sha256 !== digest(readFileSync(join(directory, name)))) throw new Error(`Rescue release binding mismatch: ${name}`);
  }
  // Preserve the existing Agent assets on other platforms. Only Linux Host
  // publication is added here; stable release and other Host targets are unchanged.
  const assets = names.filter(name => name.startsWith('komari-agent-') ||
    /^komari-host-linux-(386|amd64|arm|arm64|loong64)(\.sha256)?$/.test(name)).sort();
  const checksums = assets.map(name => {
    if (!/^[a-zA-Z0-9_.-]+$/.test(name) || !lstatSync(join(directory, name)).isFile()) {
      throw new Error(`Invalid snapshot asset: ${name}`);
    }
    return `${digest(readFileSync(join(directory, name)))}  ${name}\n`;
  }).join('');
  writeFileSync(join(directory, 'SHA256SUMS'), checksums);
  return [...assets, 'SHA256SUMS'].map(name => join(directory, name));
}

module.exports = { prepareSnapshotAssets, linuxArchitectures };
if (require.main === module) {
  try {
    for (const asset of prepareSnapshotAssets(resolve(process.argv[2] || 'artifacts'), process.argv[3])) console.log(asset);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
