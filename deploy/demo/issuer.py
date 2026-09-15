#!/usr/bin/env python3
"""VM219-only seat issuer. Durable state is the root-owned authorized_keys file."""
import base64,datetime,fcntl,hashlib,hmac,http.server,importlib.util,json,os,re,struct,time,uuid
from pathlib import Path
KEYS=Path('/etc/ssh/authorized_keys.d/virp-demo')
SECRET=Path('/etc/virp-demo-issuer/site.hmac')

def key_info(value):
    if not isinstance(value,str) or len(value.encode())>1024 or '\n' in value or '\r' in value:
        raise ValueError('invalid public key')
    parts=value.split()
    if len(parts)<2 or parts[0] not in ('ssh-ed25519','ecdsa-sha2-nistp256','ecdsa-sha2-nistp384','ecdsa-sha2-nistp521'):
        raise ValueError('ed25519 or ECDSA public key required')
    try:
        raw=base64.b64decode(parts[1],validate=True); pos=0
        def field():
            nonlocal pos
            if pos+4>len(raw):raise ValueError('short key')
            n=struct.unpack('>I',raw[pos:pos+4])[0];pos+=4
            v=raw[pos:pos+n];pos+=n
            if len(v)!=n:raise ValueError('short key')
            return v
        kind=field().decode()
        if kind!=parts[0]:raise ValueError('key type mismatch')
        if kind=='ssh-ed25519':
            if len(field())!=32:raise ValueError('invalid ed25519 length')
        else:
            curve=field().decode();point=field()
            lengths={'nistp256':65,'nistp384':97,'nistp521':133}
            if kind!='ecdsa-sha2-'+curve or len(point)!=lengths.get(curve) or point[0]!=4:raise ValueError('invalid curve point')
            # ssh-keygen additionally validates curve membership below in the HTTP path.
        if kind.startswith("ecdsa-"):
            import subprocess
            check=subprocess.run(["ssh-keygen","-lf","/dev/stdin"],input=(parts[0]+" "+parts[1]+"\n").encode(),capture_output=True)
            if check.returncode:raise ValueError("invalid curve point")
        if pos!=len(raw):raise ValueError('trailing key bytes')
    except (ValueError,UnicodeError,struct.error) as e:raise ValueError('malformed public key') from e
    return parts[0]+' '+base64.b64encode(raw).decode(), 'SHA256:'+base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')

def signed_request(raw,signature,secret,now):
    if not isinstance(signature,str) or not hmac.compare_digest(hmac.new(secret,raw,hashlib.sha256).hexdigest(),signature):
        raise ValueError('invalid request signature')
    d=json.loads(raw)
    if set(d)!={'name','email','pubkey','ts'} or type(d['ts']) is not int or abs(now-d['ts'])>120:raise ValueError('invalid or expired request')
    if not isinstance(d['name'],str) or not 1<=len(d['name'])<=120:raise ValueError('invalid name')
    if not isinstance(d['email'],str) or len(d['email'])>254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',d['email']):raise ValueError('invalid email')
    return d

def gate_event(event):
    # Installed shell has no .py suffix.
    from importlib.machinery import SourceFileLoader
    m=SourceFileLoader('issuer_gate','/usr/local/lib/virp/virp-shell').load_module()
    body=json.dumps(event,sort_keys=True,separators=(',',':'))
    reply=m.decode_reply(m.gate({'action':'chain_append','artifact_type':'evidence_item','artifact_id':'signup-'+uuid.uuid4().hex,'session_id':'demo-signup:'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d'),'artifact_content':body,'artifact_hash':hashlib.sha256(body.encode()).hexdigest()},'/run/virp/onode.sock'))
    if reply.get('kind')=='error' or reply.get('obs_type_name')=='error':raise RuntimeError('gate refused issuer evidence')
    result=json.loads(reply.get('text','{}'))
    if 'sequence' not in result:raise RuntimeError('gate evidence receipt missing')
    return result

class Issuer:
    def __init__(self,path=KEYS,evidence=gate_event,clock=time.time):self.path=Path(path);self.evidence=evidence;self.clock=clock
    def event(self,event,seat='',fp='',email='',expiry='',**detail):
        return self.evidence(dict(schema='virp-demo-signup/1',event=event,seat_id=seat,key_fingerprint=fp,email_sha256=hashlib.sha256(email.encode()).hexdigest() if email else seat[:64] if len(seat)==96 else '',expires_at=expiry,**detail))
    def prune(self):
        now=datetime.datetime.fromtimestamp(self.clock(),datetime.timezone.utc).strftime('%Y%m%d%H%M')
        with self.path.open('r+') as f:
            fcntl.flock(f,fcntl.LOCK_EX);lines=f.readlines();keep=[];removed=[]
            for line in lines:
                match=re.search(r'expiry-time="(\d{12})"',line)
                if ' demo:' in line and match and match[1]<=now:removed.append(line)
                else:keep.append(line)
            for line in removed:
                m=re.search(r'(ssh-ed25519|ecdsa-sha2-\S+) ([A-Za-z0-9+/=]+) demo:([a-f0-9]+)',line)
                fp=key_info(m[1]+' '+m[2])[1] if m else ''
                self.event('expiry-prune',m[3] if m else '',fp,expiry=re.search(r'expiry-time="(\d{12})"',line)[1],phase='authorized')
            if removed:f.seek(0);f.write(''.join(keep));f.truncate();f.flush();os.fsync(f.fileno())
            return len(removed)
    def issue(self,d):
        email=d.get('email','');seat=hashlib.sha256(email.encode()).hexdigest()+uuid.uuid4().hex;fp=''
        try:
            key,fp=key_info(d['pubkey'])
            now=int(self.clock());expires=datetime.datetime.fromtimestamp(now+86400,datetime.timezone.utc)
            expiry=expires.strftime('%Y%m%d%H%M')
            with self.path.open('r+') as f:
                fcntl.flock(f,fcntl.LOCK_EX);original=f.read();live=0
                for line in original.splitlines():
                    m=re.search(r'expiry-time="(\d{12})"',line)
                    if not line.strip() or line.lstrip().startswith('#'):continue
                    if key in line:raise ValueError('key already registered')
                    if not m or m[1]>datetime.datetime.fromtimestamp(now,datetime.timezone.utc).strftime('%Y%m%d%H%M'):live+=1
                if live>=50:raise ValueError('demo has 50 live seats')
                # Durable authorization precedes granting SSH access; it does not assert login.
                receipt=self.event('issue',seat,fp,email,expiry,phase='authorized')
                f.seek(0,2)
                f.write(('\n' if original and not original.endswith('\n') else '')+'restrict,pty,expiry-time="'+expiry+'",command="/usr/local/bin/virp-shell" '+key+' demo:'+seat+'\n')
                f.flush();os.fsync(f.fileno())
            return dict(seat_id=seat,expires_at=datetime.datetime.strptime(expiry,'%Y%m%d%H%M').replace(tzinfo=datetime.timezone.utc).isoformat(),host='216.234.102.178',ssh_command='ssh -tt -i ./virp-demo-key virp-demo@216.234.102.178',docket_url='/demo/session/'+seat,receipt=receipt)
        except ValueError as e:
            self.event('refusal',seat,fp,email,reason=str(e));raise

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args):pass  # Never log visitor PII, signatures or request bodies.
    def do_POST(self):
        try:
            if self.path!='/issue':raise ValueError('unknown route')
            n=int(self.headers.get('Content-Length','0'))
            if n<1 or n>4096:raise ValueError('request size')
            raw=self.rfile.read(n)
            try:d=signed_request(raw,self.headers.get('X-VIRP-Signature',''),SECRET.read_bytes(),int(time.time()))
            except (ValueError,TypeError) as e:
                self.server.issuer.event('refusal',reason=str(e));raise ValueError('invalid request')
            result=self.server.issuer.issue(d);code=201
        except (ValueError,KeyError):result={'error':'Request refused; check the key or try later.'};code=400
        except Exception:result={'error':'Evidence unavailable; no seat confirmed.'};code=503
        data=json.dumps(result).encode();self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)

if __name__=='__main__':
    import sys
    if '--prune' in sys.argv:print('pruned',Issuer().prune())
    else:
        server=http.server.ThreadingHTTPServer(('127.0.0.1',8090),Handler);server.issuer=Issuer();server.serve_forever()
