const { createHash } = require('node:crypto');
const { lstatSync, readFileSync, readdirSync, writeFileSync } = require('node:fs');
const { join, resolve } = require('node:path');

const linuxArchitectures = ['386', 'amd64', 'arm', 'arm64', 'loong64'];
const digest = data => createHash('sha256').update(data).digest('hex');

// The Linux installer requires both components and their individual checksums
// from one tag, even for an update or a metrics-only installation.
function prepareSnapshotAssets(directory) {
  const names = readdirSync(directory);
  const required = linuxArchitectures.flatMap(arch =>
    ['komari-agent', 'komari-host'].map(component => `${component}-linux-${arch}`));
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
    for (const asset of prepareSnapshotAssets(resolve(process.argv[2] || 'artifacts'))) console.log(asset);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
