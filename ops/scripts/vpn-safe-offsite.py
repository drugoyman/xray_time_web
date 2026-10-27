#!/usr/bin/python3
import datetime, fcntl, hashlib, json, os, pathlib, subprocess
os.umask(0o077)
lock=open('/run/lock/vpn-safe-offsite.lock','w');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
base=pathlib.Path('/var/backups/vpn-safe')
out=base/'offsite-outbox';out.mkdir(mode=0o700,exist_ok=True)
state=pathlib.Path('/var/lib/vpn-safe/offsite.json')
config='/etc/vpn-safe/rclone.conf'
recipient='/etc/vpn-safe/backup-recipient.pub'
remote='yugoo-drive:VPN-Backups-yugoo.su'
def run(args,timeout=180):
 p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if p.returncode:
  pathlib.Path('/var/lib/vpn-safe/offsite-error.log').write_text(p.stderr)
  raise RuntimeError('Command failed: '+args[0]+' '+args[1]+'; see /var/lib/vpn-safe/offsite-error.log')
 return p.stdout
def rclone(*args):
 return run(['/usr/local/bin/rclone','--config',config,'--bwlimit','2M','--transfers','1','--checkers','2','--retries','3','--low-level-retries','3','--contimeout','15s','--timeout','60s',*args],timeout=600)
try:
 archives=sorted(base.glob('vpn-*.tar.gz'),key=lambda p:p.stat().st_mtime)
 if not archives:raise RuntimeError('No local backup archive')
 archive=archives[-1]
 if datetime.datetime.now().timestamp()-archive.stat().st_mtime>36*3600:raise RuntimeError('Local backup too old')
 actual=hashlib.sha256(archive.read_bytes()).hexdigest()
 expected=pathlib.Path(str(archive)+'.sha256').read_text().split()[0]
 if actual!=expected:raise RuntimeError('Local archive checksum mismatch')
 files=[(archive,'configuration')]
 baseline=base/'images/3x-ui-baseline-20261026.tar.gz'
 if baseline.exists():files.append((baseline,'images'))
 uploaded=[]
 for source,folder in files:
  encrypted=out/(source.name+'.age')
  if not encrypted.exists():
   partial=pathlib.Path(str(encrypted)+'.partial')
   if partial.exists():raise RuntimeError('Partial encrypted archive present; inspect before retry')
   run(['/usr/bin/age','-R',recipient,'-o',str(partial),str(source)],timeout=180)
   partial.rename(encrypted)
  dest=remote+'/'+folder+'/'+encrypted.name
  checksum=hashlib.sha256(encrypted.read_bytes()).hexdigest()
  md5=hashlib.md5(encrypted.read_bytes()).hexdigest()
  sha=pathlib.Path(str(encrypted)+'.sha256');sha.write_text(checksum+'  '+encrypted.name+'\n')
  rclone('copyto',str(encrypted),dest,'--immutable')
  remote_md5=rclone('md5sum',dest).split()[0]
  if remote_md5.lower()!=md5:raise RuntimeError('Google Drive checksum mismatch')
  rclone('copyto',str(sha),dest+'.sha256','--immutable')
  uploaded.append({'file':encrypted.name,'bytes':encrypted.stat().st_size,'remote':dest,'sha256':checksum,'remote_md5_verified':True})
 status={'last_success':datetime.datetime.now(datetime.timezone.utc).isoformat(),'remote_folder':'VPN-Backups-yugoo.su','files':uploaded,'last_error':None}
 state.write_text(json.dumps(status,indent=2))
 print(json.dumps(status))
except Exception as error:
 status=json.loads(state.read_text()) if state.exists() else {}
 status['last_error']=str(error);status['last_attempt']=datetime.datetime.now(datetime.timezone.utc).isoformat()
 state.parent.mkdir(parents=True,exist_ok=True);state.write_text(json.dumps(status,indent=2))
 raise
