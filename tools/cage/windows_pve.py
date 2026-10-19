#!/usr/bin/python3 -I
"""Pinned provisioning endpoint. Caller can only observe or reserve one new VM.
The async recipe is a privileged fixed operation, not arbitrary guest execution.
"""
import os,sys,json,pathlib,subprocess,fcntl,time,uuid,hashlib,socket,base64,secrets
P=pathlib.Path
MODULES=P('/usr/local/lib/kestrel-windows');ROOT=P('/var/lib/kestrel-windows');VMID=233
MID='0dc4ddd38afb4f5090c3089dd5bdf7d9';TARGET='colo-windows2025'
sys.path.insert(0,str(MODULES))
from windows_policy import command_action, installation_media_detached

def atomic(path,value):
 tmp=path.with_suffix('.tmp');data=json.dumps(value,sort_keys=True).encode()
 with open(tmp,'wb') as f:os.chmod(tmp,0o600);f.write(data);f.flush();os.fsync(f.fileno())
 os.replace(tmp,path);fd=os.open(path.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def state():return json.loads((ROOT/'state.json').read_text()) if (ROOT/'state.json').exists() else {'phase':'unallocated','verified':False}
def update(**values):
 s=state();s.update(values,updated=time.time());atomic(ROOT/'state.json',s);return s
def journal(event):
 path=ROOT/'journal.jsonl'
 with open(path,'a') as f:f.write(json.dumps({'time':time.time(),**event},sort_keys=True)+'\n');f.flush();os.fsync(f.fileno())
def check_stop():
 if (ROOT/'STOP').exists():raise ValueError('scope_stopped')
def command(args,timeout=60):
 check_stop();journal({'command':args,'event':'dispatch'})
 r=subprocess.run(args,capture_output=True,text=True,timeout=timeout,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
 journal({'event':'result','rc':r.returncode,'output_sha256':hashlib.sha256((r.stdout+r.stderr).encode()).hexdigest()})
 if r.returncode:raise ValueError('command_failed_'+args[0].split('/')[-1])
 return r.stdout

def pinned():
 d=dict(l.split(': ',1) for l in P('/etc/pve/qemu-server/233.conf').read_text().splitlines() if ': ' in l)
 s=state()
 if d.get('name')!='kestrel-ws2025-233' or d.get('smbios1')!='uuid='+s['uuid'] or not d.get('net0','').startswith('e1000=02:54:4C:49:02:33,'):raise ValueError('guest_identity_changed')
 return d
class Agent:
 def __enter__(self):
  pinned();self.s=socket.socket(socket.AF_UNIX);self.s.settimeout(8);self.s.connect('/run/qemu-server/233.qga');self.f=self.s.makefile('rwb',buffering=0);return self
 def __exit__(self,*a):self.f.close();self.s.close()
 def q(self,c,a=None):
  ident=uuid.uuid4().hex;self.f.write(json.dumps({'execute':c,'arguments':a or {},'id':ident}).encode()+b'\n')
  for _ in range(30):
   r=json.loads(self.f.readline())
   if r.get('id')!=ident:continue
   if 'error' in r:raise ValueError('guest_agent_'+str(r['error'].get('class','error')))
   return r['return']
  raise ValueError('guest_agent_unbound_reply')
 def read(self,path):
  h=self.q('guest-file-open',{'path':path,'mode':'rb'})
  try:
   r=self.q('guest-file-read',{'handle':h,'count':32768})
   if not r.get('eof') and r.get('count',0)>=32768:raise ValueError('guest_file_too_large')
   return base64.b64decode(r['buf-b64']).decode('utf-8-sig')
  finally:self.q('guest-file-close',{'handle':h})
 def write(self,path,data):
  h=self.q('guest-file-open',{'path':path,'mode':'wb'})
  try:self.q('guest-file-write',{'handle':h,'buf-b64':base64.b64encode(data).decode()})
  finally:self.q('guest-file-close',{'handle':h})
def wait_file(path,timeout):
 end=time.monotonic()+timeout
 while time.monotonic()<end:
  check_stop()
  try:
   with Agent() as a:return json.loads(a.read(path))
  except (OSError,ValueError,EOFError):time.sleep(10)
 raise ValueError('guest_readiness_timeout')
def verify(label):
 script=(MODULES/'windows_verify.ps1').read_text().replace('VERIFY_FILE',label+'.json')
 with Agent() as a:
  a.write('C:\\ProgramData\\KestrelProvision\\verify-'+label+'.ps1',script.encode('utf-8-sig'))
  a.q('guest-exec',{'path':'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe','arg':['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File','C:\\ProgramData\\KestrelProvision\\verify-'+label+'.ps1'],'capture-output':False})
 r=wait_file('C:\\ProgramData\\KestrelProvision\\'+label+'.json',180)
 if not r.get('success') or 'Windows Server 2025' not in r.get('os','') or r.get('hostname')!='KESTREL-WS233' or r.get('uuid','').lower()!=state()['uuid']:raise ValueError('windows_identity_verification_failed')
 for k in ['secure_boot','tpm_present','tpm_ready','defender','autologon_disabled','autologon_secret_absent','answer_files_absent','rdp_running','agent_running']:
  if r.get(k) is not True:raise ValueError('windows_check_failed_'+k)
 if r.get('firewalls')!=[True,True,True] or '10.0.50.233' not in r.get('ips',[]):raise ValueError('network_security_verification_failed')
 atomic(ROOT/(label+'.json'),r);return r

def worker():
 with open(ROOT/'worker.lock','a') as l:
  fcntl.flock(l,fcntl.LOCK_EX|fcntl.LOCK_NB)
  if state()['phase']!='reserved':raise ValueError('worker_already_dispatched')
  check_stop();update(phase='preparing')
  try:
   if P('/etc/pve/qemu-server/233.conf').exists():raise ValueError('vm_slot_occupied')
   if int(dict(line.split(':',1) for line in P('/proc/meminfo').read_text().splitlines())['MemAvailable'].split()[0])<10*1024*1024:raise ValueError('insufficient_memory')
   policy=json.loads((MODULES/'policy.json').read_text())
   for name,digest in policy['media'].items():
    h=hashlib.sha256()
    with P(name).open('rb') as f:
     for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
    if h.hexdigest()!=digest:raise ValueError('media_identity_changed')
   for name,digest in policy['files'].items():
    if hashlib.sha256((MODULES/name).read_bytes()).hexdigest()!=digest:raise ValueError('recipe_changed')
   secret=ROOT/'administrator.json';pw=secrets.token_urlsafe(30)+'aA9!';atomic(secret,{'username':'Administrator','password':pw,'vmid':233,'uuid':state()['uuid']})
   media=ROOT/'answer';media.mkdir(mode=0o700)
   xml=(MODULES/'unattend.xml').read_text().replace('REDACTED',pw).replace('TLI-WS2025','KESTREL-WS233')
   (media/'Autounattend.xml').write_text(xml);(media/'bootstrap.ps1').write_bytes((MODULES/'windows_bootstrap.ps1').read_bytes());pw=None
   iso='/var/lib/vz/template/iso/kestrel-windows233-answer.iso'
   command(['/usr/bin/genisoimage','-quiet','-J','-R','-V','KESTREL_INSTALL','-o',iso,str(media)])
   os.chmod(iso,0o600)
   update(phase='creating')
   command(['/usr/sbin/qm','create','233','--name','kestrel-ws2025-233','--smbios1','uuid='+state()['uuid'],'--memory','8192','--balloon','0','--cores','4','--cpu','host','--bios','ovmf','--machine','q35','--ostype','win11','--efidisk0','local-zfs:1,efitype=4m,pre-enrolled-keys=1','--tpmstate0','local-zfs:1,version=v2.0','--sata0','local-zfs:80,discard=on,ssd=1','--ide0','iso-store:iso/windows-server-2025-eval.iso,media=cdrom','--ide1','iso-store:iso/virtio-win.iso,media=cdrom','--ide2','local:iso/kestrel-windows233-answer.iso,media=cdrom','--net0','e1000=02:54:4C:49:02:33,bridge=vmbr0,firewall=1,tag=50','--agent','enabled=1','--vga','std','--boot','order=sata0;ide0','--onboot','0','--description','Kestrel VIRP Windows2025 provisioning; owner authorized 20261019; slot233'],120)
   pinned();P('/etc/pve/firewall/233.fw').write_bytes((MODULES/'guest.fw').read_bytes())
   command(['/usr/sbin/pve-firewall','compile'])
   command(['/usr/sbin/qm','start','233']);time.sleep(3)
   for _ in range(4):command(['/usr/sbin/qm','sendkey','233','ret']);time.sleep(1)
   update(phase='installing',ip='10.0.50.233',vmid=233)
   r=wait_file('C:\\ProgramData\\KestrelProvision\\bootstrap.json',2400)
   if r.get('success') is not True:raise ValueError('bootstrap_failed')
   update(phase='verifying');before=verify('before')
   pinned();command(['/usr/sbin/qm','set','233','--ide0','none,media=cdrom','--ide1','none,media=cdrom','--ide2','none,media=cdrom','--boot','order=sata0'])
   P(iso).unlink();(media/'Autounattend.xml').unlink();(media/'bootstrap.ps1').unlink();media.rmdir()
   update(phase='rebooting',before_boot=before['boot'])
   command(['/usr/sbin/qm','reboot','233','--timeout','120'],150)
   time.sleep(25)
   # QGA may not be back when qm reports a queued reboot.
   end=time.monotonic()+360
   while True:
    try:
     with Agent() as a:a.q('guest-ping')
     break
    except (OSError,ValueError):
     if time.monotonic()>end:raise ValueError('reboot_agent_timeout')
     time.sleep(10)
   after=verify('after')
   if after['boot']==before['boot']:raise ValueError('reboot_not_verified')
   config=pinned()
   if not installation_media_detached(config):raise ValueError('media_detach_not_verified')
   journal({'event':'verified_complete','before_boot':before['boot'],'after_boot':after['boot'],'uuid':state()['uuid']})
   update(phase='complete',verified=True,verification=after,before_boot=before['boot'],after_boot=after['boot'],credential_reference='/var/lib/kestrel-windows/administrator.json (hypervisor root only)',journal_sha256=hashlib.sha256((ROOT/'journal.jsonl').read_bytes()).hexdigest())
  except Exception as e:
   update(phase='failed',verified=False,reason=str(e) if isinstance(e,ValueError) else type(e).__name__);journal({'event':'failed','reason':state()['reason']});raise

def main():
 if os.geteuid()!=0 or P('/etc/machine-id').read_text().strip()!=MID:raise ValueError('host_identity_denied')
 os.umask(0o077)
 if len(sys.argv)==2 and sys.argv[1]=='--worker':
  if os.environ.get('SUDO_USER'):raise ValueError('worker_caller_denied')
  worker();return
 if os.environ.get('SUDO_USER')!='kestrel-windows' or len(sys.argv)!=2:raise ValueError('caller_identity_denied')
 action=command_action(sys.argv[1])
 with open(ROOT/'lock','a') as l:
  fcntl.flock(l,fcntl.LOCK_EX|fcntl.LOCK_NB);s=state()
  if action=='provision':
   check_stop()
   if s['phase']!='unallocated' or P('/etc/pve/qemu-server/233.conf').exists():raise ValueError('allocation_already_exists')
   s=update(phase='reserved',uuid=str(uuid.uuid4()),verified=False,recipe='windows2025-v2',authorization_sha256=json.loads((MODULES/'policy.json').read_text())['authorization_sha256'])
   journal({'event':'reserved','uuid':s['uuid']})
   subprocess.run(['/usr/bin/systemctl','start','kestrel-windows-provision.service'],capture_output=True,check=True,timeout=15)
  s=state()
  if s['phase']=='complete':pinned()
  print(json.dumps({'ok':True,'target':TARGET,**s}))
if __name__=='__main__':
 try:main()
 except Exception as e:
  print(json.dumps({'ok':False,'target':TARGET,'reason':str(e) if isinstance(e,ValueError) else type(e).__name__}));sys.exit(1 if '--worker' in sys.argv else 0)
