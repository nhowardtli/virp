#!/bin/bash
set -euo pipefail
cd /opt/virp
python3 -c 'import sys; sys.path.insert(0,"deploy/demo"); from network import require_demo_vm; require_demo_vm()'
getent group virp >/dev/null || groupadd --system virp
id virp >/dev/null 2>&1 || useradd --system -g virp --home-dir /var/lib/virp --shell /usr/sbin/nologin virp
id virp-shell >/dev/null 2>&1 || useradd --system --uid 988 -g virp --home-dir /nonexistent --shell /usr/sbin/nologin virp-shell
id virp-demo >/dev/null 2>&1 || useradd --uid 1500 --create-home --shell /bin/sh virp-demo
[ "$(id -u virp-demo)" = 1500 ]
usermod --shell /bin/sh virp-demo
install -d -m 0750 -o virp -g virp /var/lib/virp /etc/virp/keys
install -d -m 0700 /etc/virp-demo/approval
make install-prod
make install-devices-template VIRP_DEVICES_TEMPLATE_SRC=deploy/devices.demo.template.json
make install-virp-shell
# Shared guest journal can retain yesterday's command text after chain reset.
# Visitors get signed gate output, not access to previous visitors' journals.
gpasswd -d virp-shell systemd-journal >/dev/null 2>&1 || true
install -m 0644 docs/demo/WELCOME.txt /etc/virp-demo/WELCOME.txt
# Public MOTD must be accessible to the seat; secret subdirectories stay 0700.
chmod 0755 /etc/virp-demo
if [ ! -f /etc/virp-demo/approval/demo.key ]; then
    /usr/local/lib/virp/virp-tool keygen approval /etc/virp-demo/approval/demo
fi
/usr/local/lib/virp/virp-tool enroll --key /etc/virp-demo/approval/demo.pub --operator DEMO-ONLY > /etc/virp-demo/approval/entry.json
python3 - <<'PY'
import json, os
from pathlib import Path
p=Path('/etc/virp/approvers.json')
p.write_text(json.dumps([json.loads(Path('/etc/virp-demo/approval/entry.json').read_text())]))
p.chmod(0o644)
p=Path('/etc/virp/keys/chain.key')
if not p.exists():
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f: f.write(os.urandom(32))
PY
if [ ! -f /etc/virp/keys/onode.key ]; then
    /usr/local/lib/virp/virp-tool keygen okey /etc/virp/keys/onode.key
fi
chown virp:virp /etc/virp/keys/chain.key /etc/virp/keys/onode.key
install -d -m 0755 /etc/systemd/system/virp-onode.service.d
install -m 0644 deploy/virp-onode.service /etc/systemd/system/virp-onode.service
cat > /etc/systemd/system/virp-onode.service.d/demo.conf <<'CONF'
[Service]
Environment=VIRP_KNOWN_HOSTS=/etc/virp/demo-known-hosts
CONF
cat > /etc/virp-demo/shell.env <<'CONF'
VIRP_SHELL_DEMO_SESSION=1
VIRP_SHELL_MOTD=/etc/virp-demo/WELCOME.txt
CONF
chmod 0644 /etc/virp-demo/shell.env
cat > /etc/sudoers.d/virp-demo <<'CONF'
Defaults:virp-demo env_reset
Defaults:virp-demo env_file=/etc/virp-demo/shell.env
virp-demo ALL=(virp-shell) NOPASSWD: /usr/bin/python3 /usr/local/lib/virp/virp-shell
CONF
chmod 0440 /etc/sudoers.d/virp-demo
visudo -cf /etc/sudoers.d/virp-demo
install -d -m 0755 /etc/ssh/authorized_keys.d
if [ ! -f /etc/ssh/authorized_keys.d/virp-demo ]; then
    install -m 0644 /dev/null /etc/ssh/authorized_keys.d/virp-demo
fi
cat > /etc/ssh/sshd_config.d/40-virp-demo.conf <<'CONF'
Match User virp-demo
    ForceCommand /usr/local/bin/virp-shell
    AuthorizedKeysFile /etc/ssh/authorized_keys.d/virp-demo
    PermitTTY yes
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    AllowStreamLocalForwarding no
    PermitTunnel no
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AuthenticationMethods publickey
    MaxSessions 8
Match all
CONF
sshd -t
systemctl daemon-reload
systemctl reload ssh
