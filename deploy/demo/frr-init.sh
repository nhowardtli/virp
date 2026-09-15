#!/bin/sh
set -eu
# DEMO secret, created only on VM219. Never bake a password into an image.
VIRP_DEMO_FRR_PASSWORD=$(cat /run/demo-password)
id demo-frr >/dev/null 2>&1 || adduser -D -s /bin/sh demo-frr
sed -i '/^demo-frr:/s|:[^:]*$|:/bin/sh|' /etc/passwd
addgroup demo-frr frrvty 2>/dev/null || true
printf 'demo-frr:%s\n' "${VIRP_DEMO_FRR_PASSWORD}" | chpasswd
unset VIRP_DEMO_FRR_PASSWORD
passwd -l root >/dev/null
if [ ! -f /etc/ssh/.demo-hostkeys ]; then
    rm -f /etc/ssh/ssh_host_*key /etc/ssh/ssh_host_*key.pub
    ssh-keygen -A
    touch /etc/ssh/.demo-hostkeys
fi
cat > /etc/ssh/sshd_config <<'CONF'
Port 22
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication no
AllowUsers demo-frr
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PermitTTY yes
ForceCommand /demo-cli.sh
CONF
/usr/sbin/sshd -t
pgrep -x sshd >/dev/null || /usr/sbin/sshd
