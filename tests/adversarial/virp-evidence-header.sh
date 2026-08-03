#!/bin/bash
# virp-evidence-header.sh — emit the header/footer identity block required by
# the adversarial test program's evidence contract.
#
# Usage: virp-evidence-header.sh [HEADER|FOOTER]
#
# Everything here is read-only. It never touches the FortiGate (10.0.10.1) or
# the Proxmox host (10.0.10.10) — those are hard-excluded and out of scope for
# every transcript in this program.
#
# NOTE ON SECRETS: /run/virp/devices.json contains device credentials. This
# script prints only its sha256 digest, never its contents. Do not paste that
# file into a transcript.

LABEL="${1:-HEADER}"
DAEMON_BIN=/usr/local/lib/virp/virp-onode-prod
CLIENT_BIN=/opt/virp/build/virp
SOCKET=/run/virp/onode.sock
CHAIN=/var/lib/virp/chain.db
SPOOL=/var/lib/virp/approvals

echo "===================== EVIDENCE $LABEL ====================="
echo "utc                : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "hostname           : $(hostname)"

pid=$(systemctl show -p MainPID --value virp-onode 2>/dev/null)
echo "daemon pid         : ${pid:-<none>}"
echo "daemon binary      : $DAEMON_BIN"
echo "daemon sha256      : $(sha256sum "$DAEMON_BIN" 2>/dev/null | cut -d' ' -f1)"
echo "daemon exe (live)  : $(sudo readlink -f /proc/$pid/exe 2>/dev/null || echo '<unreadable>')"
echo "daemon started     : $(systemctl show -p ActiveEnterTimestamp --value virp-onode 2>/dev/null)"

echo "client binary      : $CLIENT_BIN"
echo "client sha256      : $(sha256sum "$CLIENT_BIN" 2>/dev/null | cut -d' ' -f1)"
echo "client version     : $($CLIENT_BIN version 2>&1)"
echo "git commit         : $(sudo git -C /opt/virp rev-parse --short HEAD 2>/dev/null)"
echo "git branch         : $(sudo git -C /opt/virp branch --show-current 2>/dev/null)"
echo "git dirty          : $(sudo git -C /opt/virp status --porcelain 2>/dev/null | wc -l) file(s)"

# Gate identity straight from the running daemon's own startup line, not from
# the config file — what it logged is what it loaded.
gate=$(journalctl -u virp-onode --no-pager 2>/dev/null | grep -F '[O-Node] tier gate:' | tail -1 | sed 's/.*tier gate: //')
echo "gate (from daemon) : ${gate:-<not found in journal>}"
echo "devices.json sha256: $(sha256sum /run/virp/devices.json 2>/dev/null | cut -d' ' -f1)"
echo "devices loaded     : $(journalctl -u virp-onode --no-pager 2>/dev/null | grep -F 'devices from' | tail -1 | sed 's/.*\] //')"

echo "chain db           : $CHAIN ($(stat -c %s "$CHAIN" 2>/dev/null) bytes)"
echo "chain head         :"
sudo -u virp "$CLIENT_BIN" chain tail -n 1 --db "$CHAIN" 2>&1 | sed 's/^/    /'

for d in proposals approvals challenges; do
    printf 'spool %-11s: %s\n' "$d" "$(sudo ls -1 "$SPOOL/$d" 2>/dev/null | wc -l)"
done

echo "witness counters   :"
for c in clab-frr-ospf-frr1 clab-frr-ospf-frr2 clab-frr-ospf-frr3 clab-frr-ospf-frr4; do
    n=$(docker exec "$c" cat /var/log/virp-witness/counter 2>/dev/null || echo '<none>')
    f=$(docker exec "$c" sh -c 'test -f /etc/ssh/sshd_config.d/99-virp-witness.conf && echo on || echo OFF' 2>/dev/null)
    printf '    %-22s counter=%-6s forcecommand=%s\n' "$c" "${n:-0}" "$f"
done
echo "==========================================================="
