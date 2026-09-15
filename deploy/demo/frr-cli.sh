#!/bin/sh
# Fake-fleet adapter: expose the demo's single-line operation to real FRR.
# No shell evaluation, no arbitrary config, no save-to-startup command.
set -eu
host=$(hostname)
printf '\nFRR demo adapter — real vtysh output; eth1 description changes only.\n'
while :; do
    printf '%s# ' "$host"
    IFS= read -r line || exit 0
    line=$(printf '%s' "$line" | tr -d '\r')
    case "$line" in
        ''|'terminal length 0'|enable) ;;
        exit|quit) exit 0 ;;
        'show '*) /usr/bin/vtysh -c "$line" || printf '%% Read failed\n' ;;
        'interface eth1 description hello-from-'*)
            value=${line#interface eth1 description }
            case "$value" in *[!a-zA-Z0-9_-]*|'') printf '%% Invalid description\n'; continue;; esac
            if [ "${#value}" -gt 80 ]; then printf '%% Description too long\n'; continue; fi
            /usr/bin/vtysh -c 'configure terminal' -c 'interface eth1' -c "description $value" -c end || { printf '%% Description operation failed\n'; continue; }
            printf 'FRR demo adapter applied: interface eth1 / description %s\n' "$value"
            ;;
        *) printf '%% Unknown command (demo supports show and eth1 description only)\n' ;;
    esac
done
