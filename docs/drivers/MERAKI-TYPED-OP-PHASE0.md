# Meraki typed-op driver, Phase 0

Research note, 2026-09-03. No code. Decides what a Meraki driver would
inherit from the PBS reference driver, what its tier table looks like, and
the one property it cannot have without OAuth.

## What it takes from PBS

`include/virp_driver_pbs.h` is the reference implementation of typed
operations, and Meraki wants nearly all of it unchanged.

**The grammar.** PBS takes `pbs op=<operation.id>[ <key>=<value>]...`:
literal leading token, single spaces, keys sorted strictly ascending after
`op`, each key at most once, only the keys the op table declares. Values
admit `[A-Za-z0-9._-]` only, so a value can never carry a path segment, a
query, a percent-escape or a header-injection sequence into the derived
URL. Meraki takes this verbatim with `meraki` as the leading token.

The charset matters more here, because Meraki path parameters are
interpolated directly (`/organizations/{organizationId}/networks`). Org
and network ids and `XXXX-XXXX-XXXX` serials all fit it already.

**Method and URL derived inside the driver.** PBS derives both from a
static op table, never from input, so the approved object fully determines
the wire request and byte identity and semantic identity coincide. This is
the property the whole exercise exists to preserve, and it is the reason a
Meraki driver must not take a Dashboard API path as its command the way
`driver_librenms.c` and `driver_wazuh.c` take paths.

**GET only, enforced twice.** PBS declares no write operation at any tier;
the method is a typed enum whose only value is GET and the transport
re-checks it. Meraki v1 does the same.

**TLS pinning is the one thing that does not transfer.** PBS pins a
per-device certificate fingerprint. Meraki is one multi-tenant cloud
endpoint (`https://api.meraki.com/api/v1`, regional variants for Canada,
China, India and US FedRAMP) behind a commercial CA, so fingerprint
pinning is the wrong shape. The replacement is CA verification against a
pinned root plus a pinned hostname, keeping PBS's rule that no insecure
option exists: not a flag, not a field, not an environment variable.

## Tier table shape

One row per `capability_id`, not per path prefix. The upstream MCP server
already establishes `capability_id` as the unit of address, and the
capability list is a static artifact we can tier from directly:
`cisco_meraki_mcp/specs/meraki.json.gz` is a checked-in OpenAPI 3 document,
and `providers/openapi.py` builds each endpoint from it with
`collect_get_operations()` taking non-deprecated GET operations only and
`build_endpoint()` hardcoding `method="GET"`. So the candidate set is
enumerable offline and stable per release, which is what a tier table needs.

Default GREEN for GET, with named exceptions. The exceptions are the point,
and they are not a prefix rule, because "returns a secret" does not follow
path shape:

| capability | tier | why |
|---|---|---|
| most `get*` capabilities | GREEN | read-only inventory and telemetry |
| anything returning a PSK, passphrase or shared secret | RED | for example wireless SSID PSKs, RADIUS secrets |
| anything returning an API key, token or credential | RED | including admin and SAML material |
| anything returning client-level PII or location history | YELLOW | volume and sensitivity, not authority |
| org-wide enumerations that leak tenancy | YELLOW | breadth, not authority |

The tier table is authored, reviewed and committed. It is not derived from
the spec at runtime, because a new upstream release adding a
secret-returning GET would otherwise silently arrive as GREEN. The build
should refuse a spec whose capability set contains ids the tier table does
not name, so an unclassified capability is a build failure rather than a
default.

## What we cannot do without OAuth

We cannot bind the calling user.

The Dashboard API authenticates with a bearer token that identifies an
organization-scoped API key, not a person. `providers/meraki_client.py`
takes a single `api_key`, and `execute_api.py`'s `execute_endpoint()`
builds a short-lived client per call from one credential provider, which
resolves either an `Authorization: Bearer` header on HTTP transports or
`MERAKI_DASHBOARD_API_KEY` for stdio. Both forms carry an organization
credential. Neither carries an operator identity.

So an entry can record which key acted and cannot record who asked. Same
class of gap as the bridge session identity work: the fix is a channel
carrying identity, not a label. Meraki OAuth 2.0 is that channel; until it
is wired the driver records the calling user as unknown rather than
accepting an asserted one.

## Sandbox availability

The always-on Meraki sandbox is cloud only, no physical devices, and is
the right Phase 1 target. Reservable Small Business and Enterprise
sandboxes give exclusive access. A read-only key for the shared DevNet
organization (id `549236`) circulates in community posts but is not on the
official getting-started page: treat it as unverified. A key for an
organization you control needs API access enabled in that organization's
settings, so it needs an org, sandbox or otherwise.
