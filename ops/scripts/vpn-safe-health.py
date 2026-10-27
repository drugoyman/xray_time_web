#!/usr/bin/python3
import datetime, json, os, pathlib, shutil, socket, ssl, subprocess

os.umask(0o077)
issues = []
def run(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=15)
    return p.returncode, p.stdout.strip()

checks = {}
for unit in ['docker', 'wg-quick@wg0']:
    code, state = run(['systemctl', 'is-active', unit])
    checks[unit] = state
    if code: issues.append(unit + ' inactive')
code, state = run(['docker', 'inspect', '-f', '{{.State.Running}}', '3x-ui'])
checks['3x-ui'] = state
if code or state != 'true': issues.append('3x-ui not running')
code, state = run(['systemctl', 'is-active', 'fail2ban'])
checks['fail2ban'] = state
if code: issues.append('Fail2ban inactive')
code, logpath = run(['docker', 'inspect', '-f', '{{.LogPath}}', '3x-ui'])
if not code and logpath and pathlib.Path(logpath).is_file():
    checks['docker_log_mib'] = pathlib.Path(logpath).stat().st_size // 1048576
    if checks['docker_log_mib'] > 200: issues.append('Docker log exceeds 200 MiB; rotation maintenance needed')
for port in [443, 4200]:
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=5): pass
        checks['tcp_' + str(port)] = 'OK'
    except OSError:
        issues.append('TCP ' + str(port) + ' unavailable')
try:
    with socket.create_connection(('127.0.0.1', 443), timeout=5) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname='yugoo.su') as tls:
            cert = tls.getpeercert()
    days = int((ssl.cert_time_to_seconds(cert['notAfter']) - datetime.datetime.now().timestamp()) / 86400)
    checks['tls_days_left'] = days
    if days < 21: issues.append('TLS certificate expires in ' + str(days) + ' days')
except Exception as e:
    issues.append('TLS validation failed: ' + type(e).__name__)
try:
    ctx = ssl._create_unverified_context()
    import urllib.request
    with urllib.request.urlopen('https://127.0.0.1:4200/', context=ctx, timeout=5) as response:
        checks['panel_http'] = response.status
except Exception as e:
    issues.append('Panel HTTP failed: ' + type(e).__name__)
free = shutil.disk_usage('/').free
checks['disk_free_mib'] = free // 1048576
if free < 2 * 1024**3: issues.append('Disk free below 2 GiB')
mem = {line.split(':')[0]: int(line.split()[1]) for line in pathlib.Path('/proc/meminfo').read_text().splitlines() if len(line.split()) >= 2}
checks['memory_available_mib'] = mem['MemAvailable'] // 1024
if mem['MemAvailable'] < 100 * 1024: issues.append('Available RAM below 100 MiB')
checks['swap_total_mib'] = mem['SwapTotal'] // 1024
if not mem['SwapTotal']: issues.append('Swap missing')
backups = list(pathlib.Path('/var/backups/vpn-safe').glob('vpn-*.tar.gz'))
if not backups or datetime.datetime.now().timestamp() - max(p.stat().st_mtime for p in backups) > 36 * 3600:
    issues.append('No successful backup within 36 hours')
state = {'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'checks': checks, 'issues': issues}
path = pathlib.Path('/var/lib/vpn-safe')
path.mkdir(parents=True, exist_ok=True, mode=0o700)
(path / 'health.json').write_text(json.dumps(state, indent=2))
print(json.dumps(state))
raise SystemExit(1 if issues else 0)
