# Typed Operations — the reference pattern for VIRP REST drivers

**Status:** normative for every REST driver added after 2026-07-31.
**Reference implementation:** `src/drivers/driver_pbs.c`, `include/virp_driver_pbs.h`.
**Tests:** `tests/test_driver_pbs.c` (88), `tests/test_driver_pbs_gate.c` (74).

---

## 1. The problem this pattern exists to solve

VIRP's guarantee is that a signed observation binds the *approved thing* to
the *thing that happened*. That guarantee is only as strong as the link
between the command string the gate classified and the request the driver
actually issued.

The earlier REST drivers (`driver_wazuh.c`, `driver_librenms.c`) take an
**API path** as the command:

```
/api/v0/devices
/api/v0/alerts?state=1
```

This works, and those drivers are careful, but look at the shape of the
work they have to do. The classifier reasons about path syntax: strip the
query string, exact-match a prefix list, count segments to decide whether
`/api/v0/devices/<x>/health` has exactly one `<x>`. The driver re-derives
the same facts to build the URL. The approved object and the wire request
are related **by parsing**, and every parser is a place where the two can
come apart:

- a classifier that normalizes differently from the driver
- a path that classifies GREEN and then redirects somewhere else
- a query string ignored for matching but honoured on the wire
- a percent-escape that means one thing to the matcher and another to the
  server

None of those is hypothetical in general; they are the standard failure
modes of "classify a string, then send the string".

## 2. The rule

> **The approved object fully determines method and URL. The driver never
> parses vendor syntax.**

Concretely: the command string is not a CLI and not a URL. It is a
**canonical encoding of a typed operation** — an operation id plus named
parameters. The driver looks the id up in a **static table** that supplies
the method and the URL. Nothing else about the request derives from input.

Because the command is canonical, **byte identity and semantic identity
coincide by construction**: two different byte strings cannot denote the
same operation, so what was hashed, proposed, classified and chained is
exactly what determines the request.

## 3. The grammar

```
pbs op=<operation.id>[ <key>=<value>]...
```

- literal driver prefix, then `op=`, then zero or more `key=value`
- exactly one space between tokens; no leading or trailing space, no runs
- no quoting, no escaping, no free-form text anywhere
- `op` is first; every parameter key sorts **strictly after** `op`, and
  keys ascend by `strcmp`, so the whole token sequence is globally sorted
- each key at most once
- exactly the keys the table declares for that op — all of them, no others

Charsets are narrow and that narrowness is load-bearing:

| element | charset |
|---|---|
| operation id | `[a-z0-9.]`, no leading/trailing dot, no empty segment |
| parameter key | `[a-z0-9_]` |
| parameter value | `[A-Za-z0-9._-]` |

Note what a value **cannot** contain: `/` `?` `#` `%` `:` `@`, space, or any
control byte. A value therefore cannot introduce a path segment, a query, a
URL fragment, a percent-escape, a userinfo section, or a CR/LF header
split. This is not sanitization — nothing is stripped or rewritten. It is
refusal.

**Never normalize.** Rewriting `op=Backup.Version.Read` to lowercase, or
collapsing double spaces, would mean two byte strings denote one operation,
and the signature would no longer pin the request. Refuse instead.

## 4. The operation table

```c
typedef struct {
    const char        *id;
    pbs_method_t       method;      /* enum with ONE value: GET */
    const char        *path;        /* static; may contain "{store}" */
    const char        *query;       /* static, or NULL */
    const char *const *params;      /* NULL-terminated allowed keys */
} pbs_op_t;
```

Rules:

1. **`path` and `query` are string literals.** The only substitution is a
   declared placeholder, filled with a parameter value that has already
   passed both the grammar charset and a config allowlist.
2. **Method is a typed enum, not a string.** v1's enum has exactly one
   member, `GET`. There is no non-GET value for a table row to name or for
   a bug to select. Adding one later makes every switch a review point.
3. **The transport re-checks the method** (`pbs_method_is_allowed`). That
   turns "no write operations exist" into a property of the transport
   rather than a property of the table's current contents — and into a
   unit-testable claim rather than one a reader must establish by
   inspecting call sites.
4. **Fixed filters belong in the table, not in parameters.** The verify
   typefilter on `backup.verify.tasks` is part of what the operation *is*.
   Making it a caller parameter would let one approved op id reach a
   different task class — exactly the input-shapes-the-request property
   this pattern eliminates.
5. **RED by absence.** Every mutating endpoint is *unenumerated*, not
   enumerated-and-blocked. A future reviewer should see absence, not a row
   to soften.
6. **No redirect following.** A redirect is a URL the table did not derive.

## 5. Where each check lives

This split matters and is easy to get wrong:

| check | lives in | why |
|---|---|---|
| grammar, charset, ordering, duplicates | classifier + driver | shape is context-free |
| op id in table | classifier + driver | the table is static |
| parameter **value** vs. device allowlist | **driver only** | the gate hook is `route_command(const char *)` — it receives **no device context** and structurally cannot consult per-device config |

So: **the gate classifies the SHAPE of a request; the driver enforces the
VALUE against device config.** A well-shaped request naming a datastore
that is not allowlisted classifies GREEN and is then refused by
`pbs_build_path()` before any request is issued. That is not a gap — the
refusal is still fail-closed and still pre-network — but it *is* a boundary
worth stating rather than discovering. `tests/test_driver_pbs_gate.c`
asserts both halves in one place so the division of labour is visible.

## 6. Refusals are typed, signed, and pre-network

`pbs_execute()` parses **before** it checks whether the connection is up.
That ordering is deliberate: a malformed or unknown-op command is refused
identically whether or not the device is reachable, so the refusal is a
property of the request rather than of the moment.

Every refusal returns `VIRP_OK` with `result->success = false` and a
teaching `error_msg`, so the daemon emits a **typed signed ERROR
observation** rather than a transport error. A refused caller learns the
grammar, not just that it lost.

## 7. TLS identity

The PBS driver pins the server's **SHA-256 leaf-certificate fingerprint**,
supplied per device in `devices.json`. It refuses to connect without one,
and the daemon refuses to *load* a PBS device without one.

There is deliberately **no insecure mode**: not a flag, not an environment
variable, not a device field. `make check-pbs-pin` enforces this
mechanically — it fails if the driver ever disables curl verification,
reads *any* environment variable, drops the verify callback, or starts
following redirects.

Be honest about what the pin does and does not do. It does **not** build a
chain and does **not** check the hostname; it checks that the peer
presented exactly the recorded certificate. For a single pinned host that
is *stronger* than chain+hostname validation — a mis-issued certificate for
the right hostname from any trusted CA fails — and it is why a self-signed
PBS certificate needs no CA bundle and no exception. The cost is that
certificate rotation becomes a config change. That is the intended trade.

Contrast `driver_wazuh.c`, which carries `VIRP_WAZUH_INSECURE=1` for the
lab manager's self-signed cert. That is pre-existing and documented, and it
is precisely the shape this driver must never grow: a boolean has a value
meaning "do not check"; a fingerprint does not.

## 8. Credentials

Same pattern as the other REST drivers: the secret lives only in
`/etc/virp/autopilot.env` (0600 root), is substituted by
`deploy/render-devices.sh` into `/run/virp/devices.json` on the tmpfs
(0640 root:virp), and never touches persistent storage. The auth header is
built in a stack buffer that is `OPENSSL_cleanse`d before return and never
reaches stderr, the result struct, or an observation.

`render-devices.sh` fails the render — and therefore the daemon start — on
any unsubstituted placeholder, so a missing fingerprint or token is a loud
deploy-time error rather than an auth failure that reads like a bad
credential.

## 8a. Config entry format (PBS)

**`/etc/virp/autopilot.env`** (0600 root) — the render inputs. Every one of
these is required; `render-devices.sh` fails the render, and therefore the
daemon start, if any is missing or if any placeholder survives
substitution:

```sh
PBS_HOST=10.0.x.y                       # PBS management address
PBS_TOKENID='virp-ro@pbs!virp'          # API token id, user@realm!tokenid
PBS_TOKEN=xxxxxxxx-xxxx-...             # the token SECRET
PBS_FINGERPRINT=AB:CD:...:EF            # SHA-256 of the PBS leaf cert
PBS_DATASTORES=vault,vault-01           # comma-separated allowlist
```

**`deploy/devices.template.json`** — tracked, carries no secrets:

```json
{
  "hostname": "pbs-lab",
  "host": "${PBS_HOST}",
  "vendor": "pbs",
  "port": 8007,
  "api_port": 8007,
  "username": "${PBS_TOKENID}",
  "api_token": "${PBS_TOKEN}",
  "tls_fingerprint": "${PBS_FINGERPRINT}",
  "datastore_allow": "${PBS_DATASTORES}"
}
```

Field notes:

- **`tls_fingerprint` is mandatory.** `pbs_connect()` refuses without it and
  `load_devices()` refuses to load the device at all, with a message
  naming the reason. Accepts colon-separated or bare hex, any case.
- **There is no `verify_tls` field on a PBS device.** Do not add one.
- **`datastore_allow`** is exact-match, comma-separated. Malformed entries
  are dropped with a warning rather than silently widening the list; an
  empty list refuses `backup.snapshots.list` outright.
- **`username` holds the token id, not a login.** The auth header is
  `Authorization: PBSAPIToken=<username>:<api_token>`.
- The host must not collide with the daemon's hard-exclusion list
  (`ONODE_BLOCKED_ADDRS` in `src/virp_onode.c`); a config naming a blocked
  address is refused and the daemon does not start.

## 9. Testing obligations

A new typed-op driver is not done until it has:

- **Differential negative tests.** A negative test that passes against a
  permissive implementation tests nothing. `tests/test_driver_pbs.c`
  implements `broken_parse()` — a deliberately broken variant omitting the
  charset, ordering, duplicate, declared-parameter and table checks — and
  asserts that every refusal case is *refused by the real parser* **and**
  *accepted by the broken one*. That second half is what gives the first
  half teeth: remove a guard and the corresponding assertion fails.
- **Injection coverage:** separators, shell expansions, URL fragments,
  query smuggling, path traversal, percent-escapes, CRLF header injection,
  quoting, tabs, control bytes.
- **Canonical-form coverage:** case variants, space runs, leading/trailing
  space, prefix creep in **both** directions (`...listX` and `...lis`).
- **op-in-param smuggling:** a GREEN op id must not be able to carry a RED
  one, in either order, in a key or in a value.
- **Separator boundary:** assert both that `virp_command_check_separators()`
  rejects at the daemon ingress **and** that the driver classifier REDs it
  independently. Neither should be load-bearing alone.
- **Method impossibility:** assert the predicate rejects every value but
  GET, and that every table row is GET.

## 10. Checklist for the next REST driver

- [ ] Command is a typed-op encoding, not a path or a CLI
- [ ] Static op table; method is a typed enum; paths are literals
- [ ] Transport re-checks the method through a testable predicate
- [ ] Grammar parser refuses rather than normalizes
- [ ] Value charset excludes every URL-structural byte
- [ ] Fixed filters live in the table, not in parameters
- [ ] RED by absence; no write op at any tier without an explicit decision
- [ ] Redirects disabled
- [ ] TLS identity pinned; no insecure mode anywhere; lint enforces it
- [ ] Secret only in autopilot.env → tmpfs; cleansed after use
- [ ] Refusals are pre-network, typed, signed, and carry teaching text
- [ ] Differential negative tests with a deliberately broken variant
- [ ] Gate suite covers prefix creep, case/whitespace, op smuggling
- [ ] Doc states the shape-vs-value boundary for this driver
