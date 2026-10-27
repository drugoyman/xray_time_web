#!/usr/bin/python3
"""Check by default. --apply restores the 26 October pre-upgrade DB and image.
This interrupts Xray connections and discards post-upgrade DB changes.
System wg0 is not stopped or configured by this script.
"""
import datetime, fcntl, hashlib, json, os, pathlib, shutil, sqlite3, subprocess, sys, time
os.umask(0o077)
base=pathlib.Path('/var/backups/vpn-safe/deployments/20261026T155943Z')
source=base/'db-before/x-ui.db'
db=pathlib.Path('/root/3x-ui/3x-ui/db/x-ui.db')
compose='/etc/vpn-safe/compose-baseline.yml'
def run(args,check=True):
 p=subprocess.run(args,capture_output=True,text=True,timeout=60)
 if check and p.returncode:raise RuntimeError('Command failed: '+args[0]+' '+args[1])
 return p
def wgstate():
 files={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in pathlib.Path('/etc/wireguard').rglob('*') if p.is_file()}
 return files,run(['systemctl','show','wg-quick@wg0','-p','ActiveState','-p','ActiveEnterTimestampMonotonic']).stdout
if len(sys.argv)>2 or (len(sys.argv)==2 and sys.argv[1] not in ['--check','--apply']):raise SystemExit('Use --check or --apply')
c=sqlite3.connect('file:'+str(source)+'?mode=ro',uri=True)
assert c.execute('pragma integrity_check').fetchone()[0]=='ok','Backup integrity error'
c.close()
run(['docker','image','inspect','vpn-safe/3x-ui:baseline-20261026'])
run(['docker-compose','-p','3x-ui','-f',compose,'config','--quiet'])
for p in ['/etc/vpn-safe/panel-cert/public.key','/etc/vpn-safe/panel-cert/private.key']:
 if not pathlib.Path(p).is_file():raise RuntimeError('Panel certificate backup missing')
print('Backup and baseline image verified:',base)
if '--apply' not in sys.argv:
 print('Check only; no services or data changed. Use --apply to restore.')
 raise SystemExit(0)
lock=open('/run/lock/vpn-safe-deploy.lock','w');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
info=json.loads(run(['docker','inspect','3x-ui']).stdout)[0]
assert info['Image']=='sha256:abb840ed67b349df33ab8df3533783cb5384156f34e72b4a8bf49c2ab6bffd53','Current image differs from expected upgrade'
before=wgstate()
saved=base/('before-manual-rollback-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
saved.mkdir(mode=0o700)
run(['docker','stop','-t','10','3x-ui'])
shutil.copytree(db.parent,saved/'db')
for suffix in ['', '-wal','-shm']:
 target=pathlib.Path(str(db)+suffix);original=pathlib.Path(str(source)+suffix)
 if target.exists():target.unlink()
 if original.exists():
  shutil.copy2(original,target);os.chown(target,original.stat().st_uid,original.stat().st_gid)
run(['docker','rm','3x-ui'])
run(['docker-compose','-p','3x-ui','-f',compose,'up','-d','--no-deps','--no-build','3x-ui'])
for destination in ['/root/3x-ui/docker-compose.yml','/root/3x-ui/3x-ui/docker-compose.yml']:
 shutil.copy2(compose,destination)
time.sleep(3)
assert wgstate()==before,'System WireGuard state changed externally'
run(['/usr/local/sbin/vpn-safe-health.py'])
print('Original image and DB restored; post-upgrade DB saved:',saved)
