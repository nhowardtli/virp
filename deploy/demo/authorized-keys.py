#!/usr/bin/python3
"""StrictModes-safe reader for the deliberately issuer-writable seat file.
Only the exact demo forced-command grammar is emitted; no arbitrary options.
sshd still checks key possession and expiry-time independently.
"""
import os,re,stat,sys
from pathlib import Path
p=Path('/etc/ssh/authorized_keys.d/virp-demo')
s=p.lstat()
if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o664:sys.exit(1)
pat=re.compile(r'restrict,pty,expiry-time="[0-9]{12}",command="/usr/local/bin/virp-shell" (?:ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/=]+ demo:[a-f0-9]{96}')
for line in p.read_text().splitlines():
 if pat.fullmatch(line):print(line)
