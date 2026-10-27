#!/usr/bin/python3
import datetime, fcntl, hashlib, json, os, pathlib, shutil, signal, socket, sqlite3, ssl, subprocess, time, urllib.request
os.umask(0o077)
lock=open('/run/lock/vpn-safe-deploy.lock','w')
fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
base=pathlib.Path('/var/backups/vpn-safe/deployments')/datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
base.mkdir(parents=True,mode=0o700)
dbdir=pathlib.Path('/root/3x-ui/3x-ui/db')
db=dbdir/'x-ui.db'
candidate='/etc/vpn-safe/compose-candidate-288.yml'
baseline='/etc/vpn-safe/compose-baseline.yml'
expected_image='sha256:abb840ed67b349df33ab8df3533783cb5384156f34e72b4a8bf49c2ab6bffd53'
old_image='sha256:25ff83b842c2596442ca24f2403d25d08ebb5dd1db3bdb36690c0ae0a8723ad2'

def run(args,check=True,timeout=45):
 r=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 if check and r.returncode:
  (base/'last-command-error.log').write_text(r.stdout+r.stderr)
  raise RuntimeError('Command failed: '+args[0]+' '+args[1])
 return r

def inspect():return json.loads(run(['docker','inspect','3x-ui']).stdout)[0]
def wgfiles():return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in pathlib.Path('/etc/wireguard').rglob('*') if p.is_file()}
def wgstate():
 return run(['systemctl','show','wg-quick@wg0','-p','ActiveState','-p','ActiveEnterTimestampMonotonic']).stdout
def identity():
 c=sqlite3.connect('file:'+str(db)+'?mode=ro',uri=True)
 rows=c.execute('select id,port,protocol,enable,settings from inbounds order by id').fetchall()
 c.close()
 return hashlib.sha256(json.dumps(rows,sort_keys=True).encode()).hexdigest()
def compose(file):
 # Remove only the stopped production container. This avoids legacy Compose
 # recreation bugs with OCI image metadata; all bind-mounted data is retained.
 current=run(['docker','inspect','3x-ui'],check=False)
 if current.returncode==0:
  if json.loads(current.stdout)[0]['State']['Running']:raise RuntimeError('Refusing to remove running container')
  run(['docker','rm','3x-ui'])
 run(['docker-compose','-p','3x-ui','-f',file,'up','-d','--no-deps','--no-build','3x-ui'],timeout=60)
def check_ready(expected_ports):
 info=inspect()
 if not info['State']['Running'] or info['State']['OOMKilled']:raise RuntimeError('Container unhealthy')
 if info['Image']!=expected_image:raise RuntimeError('Unexpected image')
 text=run(['ss','-H','-lntu']).stdout
 actual=set()
 for line in text.splitlines():
  parts=line.split()
  if len(parts)>4:
   try:actual.add((parts[0],int(parts[4].rsplit(':',1)[-1])))
   except ValueError:pass
 if not expected_ports.issubset(actual):raise RuntimeError('Missing expected listeners')
 with socket.create_connection(('127.0.0.1',443),timeout=4) as raw:
  with ssl.create_default_context().wrap_socket(raw,server_hostname='yugoo.su'):pass
 with socket.create_connection(('127.0.0.1',47987),timeout=4) as raw:
  with ssl.create_default_context().wrap_socket(raw,server_hostname='yugoo.su'):pass
 with urllib.request.urlopen('https://127.0.0.1:4200/',context=ssl._create_unverified_context(),timeout=4) as response:
  if response.status!=200:raise RuntimeError('Panel HTTP error')
 if run(['docker','exec','3x-ui','/app/bin/xray-linux-amd64','run','-test','-c','/app/bin/config.json'],check=False).returncode:raise RuntimeError('Xray configuration invalid')

original=inspect()
if original['Image']!=old_image or not original['State']['Running']:raise RuntimeError('Production state differs from tested baseline')
original_wg=wgfiles();original_wgstate=wgstate();original_identity=identity()
(base/'before-inspect.json').write_text(json.dumps(original,indent=2))
config=json.loads(run(['docker','exec','3x-ui','cat','/app/bin/config.json']).stdout)
expected_ports={(('udp' if x.get('protocol')=='wireguard' else 'tcp'),int(x['port'])) for x in config['inbounds']}
expected_ports.add(('tcp',4200))
for file in [candidate,baseline]:run(['docker-compose','-p','3x-ui','-f',file,'config','--quiet'])
run(['/usr/local/sbin/vpn-safe-backup.py'],timeout=90)
stopped=False;saved=False;start=time.monotonic()
def interrupted(signum,frame):raise RuntimeError('Deployment interrupted')
signal.signal(signal.SIGTERM,interrupted)
try:
 print('Stopping Xray container for deployment; system wg0 remains active',flush=True)
 stopped=True
 run(['docker','stop','-t','10','3x-ui'])
 shutil.copytree(dbdir,base/'db-before')
 saved=True
 c=sqlite3.connect(db)
 if c.execute('pragma integrity_check').fetchone()[0]!='ok':raise RuntimeError('Database integrity error')
 row=c.execute('select id,stream_settings from inbounds where port=47987').fetchone()
 if not row:raise RuntimeError('Trojan inbound missing')
 settings=json.loads(row[1]);cert=settings['tlsSettings']['certificates'][0]
 if cert['certificateFile']!='/root/cert/yugoo.su.fullchain.pem':raise RuntimeError('Unexpected certificate path')
 cert['keyFile']='/root/cert/yugoo.su.privkey.pem'
 c.execute('update inbounds set stream_settings=? where id=?',(json.dumps(settings),row[0]));c.commit();c.close()
 compose(candidate)
 deadline=time.monotonic()+35
 last_error=None
 while time.monotonic()<deadline:
  try:check_ready(expected_ports);last_error=None;break
  except Exception as e:last_error=e;time.sleep(2)
 if last_error:raise last_error
 if identity()!=original_identity:raise RuntimeError('Inbound identities or credentials changed')
 if wgfiles()!=original_wg or wgstate()!=original_wgstate:raise RuntimeError('System WireGuard state changed')
 log=run(['docker','logs','--since','2m','3x-ui'],check=False)
 (base/'startup.log').write_text(log.stdout+log.stderr)
 if 'Failed to start:' in log.stdout+log.stderr or 'invalid X509 key pair' in log.stdout+log.stderr:raise RuntimeError('Startup error in Xray log')
 report={'result':'deployed','image':inspect()['Image'],'database_integrity':'ok','identity_preserved':True,'system_wireguard_unchanged':True,'ready_after_seconds':round(time.monotonic()-start,2),'backup_directory':str(base),'log_rotation':inspect()['HostConfig']['LogConfig']}
 (base/'result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report),flush=True)
except BaseException as error:
 print('Deployment failed; restoring original image and database: '+str(error),flush=True)
 if stopped:
  run(['docker','stop','-t','5','3x-ui'],check=False)
  if saved:
   failed=base/'db-failed';failed.mkdir()
   for suffix in ['', '-wal','-shm']:
    p=pathlib.Path(str(db)+suffix)
    if p.exists():shutil.move(str(p),str(failed/p.name))
   for suffix in ['', '-wal','-shm']:
    p=base/'db-before'/('x-ui.db'+suffix)
    if p.exists():
     dst=dbdir/p.name;shutil.copy2(p,dst);os.chown(dst,p.stat().st_uid,p.stat().st_gid)
   compose(baseline)
  else:run(['docker','start','3x-ui'])
 (base/'result.json').write_text(json.dumps({'result':'rollback_attempted','reason':str(error),'backup_directory':str(base)},indent=2))
 raise
