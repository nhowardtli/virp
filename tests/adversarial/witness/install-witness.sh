#!/bin/bash
# install-witness.sh — install/remove the target-side witness on sacrificial
# containerlab FRR containers.
#
# SCOPE / SAFETY
#   Operates ONLY on containers named on the command line, and refuses any name
#   that is not a clab-frr-* container. The hard-excluded production devices
#   (the FortiGate and the Proxmox host) are not containers and cannot be
#   reached by this script at all — but the name guard is here so that stays
#   true if someone edits the default list.
#
# WHAT IT CHANGES INSIDE EACH CONTAINER (all reversible, see `remove`)
#   /usr/local/bin/virp-witness            the witness script
#   /etc/ssh/sshd_config.d/99-virp-witness.conf   ForceCommand -> witness
#   /var/log/virp-witness/                 log, counter, lock
#   then SIGHUP to the sshd listener so new connections pick up the config.
#
# KNOWN COVERAGE BOUNDARY — READ THIS
#   sshd applies ForceCommand from the config the *listener* held when the
#   connection was accepted. The VIRP linux driver keeps a PERSISTENT SSH
#   session and opens a new exec channel per command, so a session established
#   BEFORE this install keeps running without the witness. Reloading sshd is
#   not enough. After installing you must force the daemon to reconnect
#   (restart virp-onode, or drop its sshd child) and then prove the witness is
#   catching daemon traffic. `verify` does not do this for you.

set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_TARGETS=(clab-frr-ospf-frr1 clab-frr-ospf-frr2 clab-frr-ospf-frr3 clab-frr-ospf-frr4)
WITNESS_SRC="$SELF_DIR/virp-witness"
CONF_NAME=99-virp-witness.conf

die() { echo "FATAL: $*" >&2; exit 1; }

guard_name() {
    case "$1" in
        clab-frr-*) : ;;
        *) die "refusing to touch '$1' — witness installs only on clab-frr-* sacrificial containers" ;;
    esac
    docker inspect -f '{{.State.Running}}' "$1" >/dev/null 2>&1 \
        || die "container '$1' not found or not inspectable"
}

do_install() {
    local c="$1"
    guard_name "$c"
    docker exec "$c" mkdir -p /var/log/virp-witness /usr/local/bin /etc/ssh/sshd_config.d || return 1
    docker cp "$WITNESS_SRC" "$c:/usr/local/bin/virp-witness" || return 1
    docker exec "$c" chmod 0755 /usr/local/bin/virp-witness || return 1
    docker exec "$c" sh -c 'touch /var/log/virp-witness/lock /var/log/virp-witness/witness.log; chmod 0644 /var/log/virp-witness/witness.log'
    docker exec "$c" sh -c "printf '# VIRP adversarial test program — target-side witness.\n# Every SSH exec channel is routed through the witness, which logs the\n# operation and then runs it unaltered. Remove this file to disable.\nForceCommand /usr/local/bin/virp-witness\n' > /etc/ssh/sshd_config.d/$CONF_NAME"
    docker exec "$c" /usr/sbin/sshd -t || { echo "  sshd -t FAILED on $c — rolling back config"; docker exec "$c" rm -f "/etc/ssh/sshd_config.d/$CONF_NAME"; return 1; }
    docker exec "$c" sh -c 'kill -HUP $(cat /var/run/sshd.pid 2>/dev/null || pgrep -f "sshd: /usr/sbin/sshd \[listener\]" | head -1)' \
        || echo "  WARN: could not HUP sshd on $c"
    echo "  installed: $c"
}

do_remove() {
    local c="$1"
    guard_name "$c"
    docker exec "$c" rm -f "/etc/ssh/sshd_config.d/$CONF_NAME"
    docker exec "$c" sh -c 'kill -HUP $(cat /var/run/sshd.pid 2>/dev/null || pgrep -f "sshd: /usr/sbin/sshd \[listener\]" | head -1)' || true
    echo "  removed ForceCommand: $c  (witness script and logs left in place)"
}

do_verify() {
    local c="$1"
    guard_name "$c"
    local conf script cnt
    conf=$(docker exec "$c" sh -c "cat /etc/ssh/sshd_config.d/$CONF_NAME 2>/dev/null | grep -c ForceCommand" || echo 0)
    script=$(docker exec "$c" sh -c 'test -x /usr/local/bin/virp-witness && echo yes || echo no')
    cnt=$(docker exec "$c" sh -c 'cat /var/log/virp-witness/counter 2>/dev/null || echo 0')
    printf '  %-22s ForceCommand=%s witness_exec=%s counter=%s\n' "$c" "$conf" "$script" "$cnt"
}

do_reset() {
    local c="$1"
    guard_name "$c"
    # Truncate the log and zero the counter. Use between transcripts so counts
    # start from a known baseline; never mid-test.
    docker exec "$c" sh -c ': > /var/log/virp-witness/witness.log; printf 0 > /var/log/virp-witness/counter'
    echo "  reset: $c"
}

do_dump() {
    local c="$1"
    guard_name "$c"
    docker exec "$c" sh -c 'cat /var/log/virp-witness/witness.log 2>/dev/null' | sed "s|^|$c\t|"
}

cmd="${1:-}"; shift || true
targets=("$@")
[ ${#targets[@]} -eq 0 ] && targets=("${DEFAULT_TARGETS[@]}")

case "$cmd" in
    install) [ -r "$WITNESS_SRC" ] || die "witness source not found at $WITNESS_SRC"
             for c in "${targets[@]}"; do do_install "$c"; done ;;
    remove)  for c in "${targets[@]}"; do do_remove  "$c"; done ;;
    verify)  for c in "${targets[@]}"; do do_verify  "$c"; done ;;
    reset)   for c in "${targets[@]}"; do do_reset   "$c"; done ;;
    dump)    for c in "${targets[@]}"; do do_dump    "$c"; done ;;
    *) cat >&2 <<EOF
usage: $0 {install|remove|verify|reset|dump} [container ...]
       default containers: ${DEFAULT_TARGETS[*]}

After 'install', the VIRP daemon's pre-existing persistent SSH session still
bypasses the witness. Restart virp-onode (or kill its sshd child) and then
prove capture with a real GREEN read before trusting any count.
EOF
       exit 2 ;;
esac
