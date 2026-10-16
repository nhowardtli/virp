# Explicit Cisco-compatible health probe

The root-controlled device configuration accepts `cisco_health_probe` only for
`cisco_ios` or `cisco_iosxe`: `clock` (default) or `version`. The latter supports
FRR qualification targets that reject `show clock`. Unknown values, nonstrings,
embedded NULs and use on other vendors make configuration loading fail.

The watchdog uses `show clock` or `show version` in EXEC and the corresponding
`do show ...` in configuration mode. No fallback, arbitrary probe command or
health-check bypass is provided. Command error detection remains unchanged:
FRR `% Unknown command:` remains a failed command. Explicit version probes are
listed in the signed node_config artifact. This is not a new chain format.

Deploy to the isolated canary first, after a snapshot and database/config/binary
backup. Preserve the helper STOP while qualifying. Verify multiple watchdog
cycles, a signed GREEN read, a native gated refusal and an invalid command's
signed UNKNOWN plus pending recovery marker. Do not activate a prior binary
that incorrectly treats FRR unknown commands as successes.

Large observation storage remains a separate contract: the current inline
artifact limit is 8191 bytes after base64 encoding. Retain oversized raw frames
and fail closed; do not truncate, re-sign or present them as chained evidence.
