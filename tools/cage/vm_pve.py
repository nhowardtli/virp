#!/usr/bin/python3 -I
"""Root endpoint: no shell eval; exact VM identity, durable one-shot reboot."""
import fcntl,hashlib,json,os,pathlib,subprocess,sys,time
sys.path.insert(0,'/usr/local/lib/kestrel-vm')
from vm_policy import command_action,authorize
P=pathlib.Path;ROOT=P('/var/lib/kestrel-vm231');MID='0dc4ddd38afb4f5090c3089dd5bdf7d9'
def run(args,timeout=15):
 r=subprocess.run(args,capture_output=True,text=True,timeout=timeout,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
 if r.returncode:raise ValueError('hypervisor_command_failed')
 return r.stdout

def durable(path,value):
 with open(path,'x') as f:os.chmod(path,0o600);json.dump(value,f);f.flush();os.fsync(f.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def identity():
 raw=run(['/usr/sbin/qm','config','231']);d=dict(line.split(': ',1) for line in raw.splitlines() if ': ' in line)
 if d.get('name')!='kestrel-vm-fixture' or d.get('smbios1')!='uuid=869034f4-b671-4426-8e30-d697e8c0aa23' or any(k.startswith('net') for k in d):raise ValueError('target_identity_changed')
 return {'vmid':231,'uuid':d['smbios1'],'name':d['name'],'config_sha256':hashlib.sha256(raw.encode()).hexdigest(),'hypervisor_machine_id':MID}
def status(ident):
 state=run(['/usr/sbin/qm','status','231']).strip();result={'target':'colo-vm231','identity':ident,'state':state,'guest_ready':False,'at':time.time()}
 try:
  d=json.loads(run(['/usr/sbin/qm','guest','exec','231','--timeout','8','--','/bin/cat','/etc/machine-id','/proc/sys/kernel/random/boot_id'],timeout=12))
  lines=d.get('out-data','').strip().splitlines()
  if d.get('exited') and d.get('exitcode')==0 and len(lines)==2:
   result.update(guest_ready=True,machine_id=lines[0],boot_id=lines[1])
 except (ValueError,subprocess.TimeoutExpired):pass
 return result
def main():
 if os.geteuid()!=0 or os.environ.get('SUDO_USER')!='kestrel-vm' or P('/etc/machine-id').read_text().strip()!=MID:raise ValueError('caller_identity_denied')
 os.umask(0o077)
 if len(sys.argv)!=2:raise ValueError('invalid_arguments')
 action=command_action(sys.argv[1])
 with open(ROOT/'lock','a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  ident=identity();current=status(ident)
  if action=='status':print(json.dumps({'ok':True,**current}));return
  if not current['guest_ready'] or current['state']!='status: running':raise ValueError('guest_not_ready')
  grant=json.loads((ROOT/'grant.json').read_text());authorize(grant,ident,current['boot_id'],consumed=(ROOT/'consumed.json').exists(),stopped=(ROOT/'STOP').exists())
  durable(ROOT/'consumed.json',{'grant':grant,'before':current,'at':time.time(),'outcome':'dispatch_reserved_no_retry'})
  # The API returns a task identifier promptly; we never retry an uncertain dispatch.
  raw=run(['/usr/bin/pvesh','create','/nodes/pve1/qemu/231/status/reboot','--timeout','60','--output-format','json'],timeout=15)
  task=json.loads(raw)
  if not isinstance(task,str) or not task.startswith('UPID:'):raise ValueError('invalid_task_result')
  result={'ok':True,'accepted':True,'target':'colo-vm231','task':task,'before':current,'verified_reboot':False,'at':time.time()}
  durable(ROOT/'dispatched.json',result);print(json.dumps(result))
if __name__=='__main__':
 try:main()
 except Exception as e:
  # Return a typed refusal as device output, without leaking subprocess details.
  print(json.dumps({'ok':False,'reason':str(e) if isinstance(e,ValueError) else type(e).__name__,'target':'colo-vm231'}))
