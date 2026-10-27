#!/usr/bin/python3
import datetime, fcntl, hashlib, json, os, pathlib, shutil, sqlite3, subprocess, tarfile, tempfile

os.umask(0o077)
root = pathlib.Path('/var/backups/vpn-safe')
root.mkdir(mode=0o700, parents=True, exist_ok=True)
lock = open('/run/lock/vpn-safe-backup.lock', 'w')
fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

def run(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=45)
    if p.returncode:
        raise RuntimeError('Command failed: ' + args[0])
    return p.stdout

stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
archive = root / ('vpn-' + stamp + '.tar.gz')
if shutil.disk_usage(root).free < 1024 ** 3:
    raise RuntimeError('Less than 1 GiB free; backup skipped')
with tempfile.TemporaryDirectory(prefix='.stage-', dir=root) as tmp:
    stage = pathlib.Path(tmp)
    db = stage / 'x-ui.db'
    source = sqlite3.connect('file:/root/3x-ui/3x-ui/db/x-ui.db?mode=ro', uri=True, timeout=10)
    dest = sqlite3.connect(db)
    source.backup(dest, pages=64, sleep=0.1)
    if dest.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
        raise RuntimeError('SQLite backup failed integrity check')
    source.close(); dest.close()
    captures = {
        'docker-inspect.json': ['docker', 'inspect', '3x-ui'],
        'iptables.v4': ['iptables-save'],
        'iptables.v6': ['ip6tables-save'],
        'nft-rules.txt': ['nft', 'list', 'ruleset'],
        'listeners.txt': ['ss', '-lntup'],
        'routes.txt': ['ip', 'route', 'show', 'table', 'all'],
        'wg-handshakes.txt': ['wg', 'show', 'all', 'latest-handshakes'],
        'xray-config.json': ['docker', 'exec', '3x-ui', 'cat', '/app/bin/config.json'],
    }
    for name, args in captures.items():
        (stage / name).write_text(run(args))
    paths = ['/root/3x-ui/docker-compose.yml', '/root/3x-ui/3x-ui/docker-compose.yml',
             '/root/3x-ui/3x-ui/cert', '/etc/wireguard', '/etc/letsencrypt',
             '/etc/sysctl.conf', '/etc/sysctl.d', '/etc/fstab', '/etc/ssh', '/root/.ssh/authorized_keys',
             '/etc/docker', '/etc/fail2ban', '/etc/vpn-safe', '/etc/systemd/system', '/usr/local/sbin/vpn-safe-backup.py',
             '/usr/local/sbin/vpn-safe-health.py']
    partial = pathlib.Path(str(archive) + '.partial')
    with tarfile.open(partial, 'w:gz', dereference=False) as tf:
        tf.add(stage, arcname='snapshot')
        for name in paths:
            if os.path.exists(name):
                tf.add(name, arcname='files' + name)
    with tarfile.open(partial, 'r:gz') as tf:
        if 'snapshot/x-ui.db' not in tf.getnames():
            raise RuntimeError('Database missing from archive')
    partial.rename(archive)
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
archive.with_suffix(archive.suffix + '.sha256').write_text(digest + '  ' + archive.name + '\n')
print('Backup OK:', archive.name, 'SQLite integrity OK; archive readable')
