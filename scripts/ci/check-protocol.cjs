// go.mod is the single reviewed protocol pin. Never copy its version into YAML.
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { readFileSync } = require('node:fs');
const MODULE = 'github.com/r11234567/komari-proto';

function verifyProtocol(declared, resolved, sums) {
  const pin = declared.Require?.find(entry => entry.Path === MODULE);
  assert.ok(pin?.Version && !pin.Indirect, 'protocol must be an explicit go.mod requirement');
  assert.ok(!declared.Replace?.some(entry => entry.Old.Path === MODULE), 'protocol replace is forbidden');
  assert.equal(resolved.Path, MODULE, 'resolved module path differs');
  assert.equal(resolved.Version, pin.Version, 'resolved protocol differs from go.mod');
  assert.ok(!resolved.Replace, 'resolved protocol replace is forbidden');
  for (const version of [pin.Version, `${pin.Version}/go.mod`]) {
    assert.ok(sums.split(/\r?\n/).some(line => {
      const [path, actualVersion, checksum] = line.trim().split(/\s+/);
      return path === MODULE && actualVersion === version && /^h1:\S+$/.test(checksum || '');
    }), `go.sum is missing ${MODULE} ${version}`);
  }
  return `${MODULE} ${pin.Version}`;
}

if (require.main === module) {
  const env = { ...process.env, GOWORK: 'off' };
  const goJSON = args => JSON.parse(execFileSync('go', args, { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] }));
  console.log(verifyProtocol(goJSON(['mod', 'edit', '-json']),
    goJSON(['list', '-mod=readonly', '-m', '-json', MODULE]), readFileSync('go.sum', 'utf8')));
}
module.exports = { MODULE, verifyProtocol };
