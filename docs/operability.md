# Health and enrollment

`{"action":"health","device":"name"}` selects a fixed vendor-specific read
and passes it through the ordinary requester UID, gate, and evidence path.
Unknown/unsupported vendors never receive a guessed Linux or Cisco command.

`list_fleet` retains its name/class/status fields. Status is one of:
`disabled`, `unsupported`, `not_checked`, `connecting`, `connection_failed`,
`connected_unverified`, `read_verified`, or `needs_health_check`.
A connection alone does not establish readiness. `read_verified` requires a
successful GREEN read and completed signed observation within 300 seconds.
Failures and connection loss clear that evidence; restart clears all readiness.
This describes a recent successful read, not comprehensive device health or
permission to write. Consumers must tolerate new status strings.

Use a unique `${VIRP_DEVICE_NAME_PASSWORD}`, `${VIRP_DEVICE_NAME_API_TOKEN}`,
or `${VIRP_DEVICE_NAME_ENABLE}` placeholder per credential. NAME contains only
uppercase letters, digits and underscores. Store values in the root-controlled
credential environment. Missing/empty values fail rendering. Policy and UID
placeholders remain explicitly controlled. Existing legacy names still work.

Enrollment still requires verified target identity, a least-privilege device
account, an independently verified SSH host key or TLS trust, a narrowly scoped
network path, then an actual signed read. Merely adding a registry row is not
successful enrollment. Windows and iDRAC require qualified native adapters;
mark unsupported devices honestly rather than assigning an unrelated driver.

# Wazuh TLS

Keep `VIRP_WAZUH_INSECURE=0`. Set `VIRP_CA_BUNDLE` to a root-controlled trust
bundle obtained over an independently authenticated management channel.
For a certificate whose DNS name differs from the manager IP, set that device's
`tls_servername` to the certificate name. The Wazuh driver fixes the name to
`host` using libcurl's resolve mapping; it keeps certificate and hostname
verification enabled. `host` must be an IP when `tls_servername` is used.
Wazuh requests bypass environment proxies so this address binding holds.

Renew certificates before expiry and update trust material through the same
management channel. Do not learn trust from an unverified network handshake.
`make test-wazuh-tls` proves good trust works and wrong CA/name failures send no
application authentication request, against a local test TLS server.

# Shutdown

Watchdog sleep is interruptible within approximately 100 ms, and shutdown
stops fleet traversal after the current operation. An already-running driver
operation still observes its own timeout. This does not promise instant
cancellation or permit freeing shared state beneath active workers.
