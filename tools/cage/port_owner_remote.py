"""Fixed, pinned .211-to-owner transport. No automatic retry after ambiguity.

Provisioning the account/key/forced command is a separate deployment step. This
module does not create credentials or change SSH policy. Only the trusted helper
may invoke it; the cage never receives the private transport key or SSH access.
"""
import json
import subprocess
from port_owner_service import protected
from port_transaction import Refused

HOST='kestrel-approve@10.0.20.224'
COMMAND='/usr/bin/sudo -n /usr/local/sbin/kestrel-port-owner'

def argv(private_key,known_hosts):
 return ['/usr/bin/ssh','-F','/dev/null','-T',
  '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
  '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(known_hosts),
  '-o','UpdateHostKeys=no','-o','HostKeyAlgorithms=ssh-ed25519','-o','GlobalKnownHostsFile=/dev/null','-o','ForwardAgent=no',
  '-o','ClearAllForwardings=yes','-o','ProxyCommand=none',
  '-o','ControlMaster=no','-o','ControlPath=none','-o','ConnectTimeout=10',
  '-o','PreferredAuthentications=publickey','-o','PasswordAuthentication=no',
  '-o','KbdInteractiveAuthentication=no','-i',str(private_key),HOST,COMMAND]

class RemoteOwner:
 def __init__(self,private_key,known_hosts):
  self.command=argv(protected(private_key,secret=True),protected(known_hosts))
 def call(self,request):
  return exchange(self.command,request)

def exchange(command,request,*,run=subprocess.run):
 if not isinstance(request,dict) or request.get('action') not in ('prepare','authorize','sign_envelope','sign_native','close','status'):raise Refused('invalid_owner_request')
 raw=json.dumps(request,sort_keys=True,separators=(',',':')).encode()
 if len(raw)>131072:raise Refused('owner_request_too_large')
 try:r=run(command,input=raw,capture_output=True,timeout=210,check=False)
 except (subprocess.TimeoutExpired,OSError):raise Refused('owner_transport_indeterminate_no_retry') from None
 if len(r.stdout)>131072:raise Refused('owner_response_oversized_no_retry')
 try:reply=json.loads(r.stdout)
 except (ValueError,UnicodeError):raise Refused('owner_response_indeterminate_no_retry') from None
 if not isinstance(reply,dict) or type(reply.get('ok'))is not bool:raise Refused('owner_response_indeterminate_no_retry')
 if reply['ok'] is False:
  # An explicit refusal is retained as data; never reinterpret it as approval.
  return reply
 if r.returncode!=0:raise Refused('owner_transport_indeterminate_no_retry')
 return reply
