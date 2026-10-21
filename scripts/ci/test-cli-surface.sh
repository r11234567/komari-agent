#!/usr/bin/env bash
# No services or host configuration are touched. Full output survives failures.
set -euo pipefail
log_dir="${KOMARI_CLI_LOG_DIR:-ci-artifacts/cli}"
mkdir -p "$log_dir"
log_dir="$(cd "$log_dir" && pwd)"
exec > >(tee "$log_dir/cli.log") 2>&1
trap 'status=$?; echo "$status" > "$log_dir/exit-code.txt"' EXIT
export GOMAXPROCS=1 GOMEMLIMIT=96MiB GOGC=30
go build -p=1 -o "$log_dir/komari-agent" .
for retired in --interval --enable-gpu --memory-include-cache --max-retries; do
 if bash install.sh "$retired" > "$log_dir/installer-${retired#--}.log" 2>&1; then
  echo "Installer accepted retired option $retired"; exit 1
 fi
 grep -q 'Removed agent option:' "$log_dir/installer-${retired#--}.log"
done
python3 - "$log_dir" <<'PY'
import json, os, subprocess, sys, tempfile
from pathlib import Path
logs=Path(sys.argv[1]); binary=logs/'komari-agent'
with tempfile.TemporaryDirectory(prefix='komari-cli-') as tmp:
    env={k:v for k,v in os.environ.items() if not k.startswith('AGENT_')}
    env.update(HOME=tmp, XDG_CONFIG_HOME=tmp, APPDATA=tmp)
    index=0
    def run(*args, success=True):
        global index
        index+=1
        result=subprocess.run([str(binary),'--standalone',*args],cwd=tmp,env=env,capture_output=True,text=True,timeout=20)
        (logs/f'{index:02d}.stdout.log').write_text(result.stdout)
        (logs/f'{index:02d}.stderr.log').write_text(result.stderr)
        print(f'{index:02d} {args}: exit={result.returncode}',flush=True)
        assert (result.returncode==0)==success, result.stderr
        return result
    run('--help')
    for args in [('upgrade',),('update-conf',),('rollback',),('status','privileged'),('recover','show-config'),('recover','rollback-config'),('--interval','3'),('--enable-gpu',),('--memory-include-cache',),('--detailed-gpu',),('--get-ip-addr-from-nic',)]:
        run(*args,success=False)
    local=Path(tmp)/'local.json'
    local.write_text(json.dumps({'endpoint':'https://user:do-not-print@example.invalid','token':'secret-token','cf_access_client_secret':'secret-cf','disable_remote_control':True}))
    env.update(AGENT_INTERVAL='99',AGENT_ENABLE_GPU='true')
    result=run('config','show','--config',str(local),'--json')
    data=json.loads(result.stdout)
    assert data['runtime']['report_interval']==3_000_000_000
    assert data['effective_config_from_disk']['runtime']['enable_gpu'] is False
    assert 'do-not-print' not in result.stdout and 'secret-token' not in result.stdout and 'secret-cf' not in result.stdout
    assert sorted(p.name for p in Path(tmp).iterdir())==['local.json'], 'query created state files'
    local.write_text('{"interval":3}')
    run('config','show','--config',str(local),'--json',success=False)
print('CLI removals, public JSON rejection, redaction, defaults and read-only inspection verified.')
PY
