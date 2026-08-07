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

Be honest about what the pin does and does not do. It replaces **chain
building and trust-anchor validation**: it checks that the peer presented
exactly the recorded certificate. For a single pinned host that is
*stronger* than chain validation — a mis-issued certificate for the right
name from any trusted CA fails — and it is why a self-signed PBS
certificate needs no CA bundle and no exception. The cost is that
certificate rotation becomes a config change. That is the intended trade.

**The pin does NOT replace hostname verification, and assuming it did was
a real bug.** The first version of this driver set
`CURLOPT_SSL_VERIFYHOST=2` and reasoned that, since the certificate-verify
callback overrides OpenSSL's chain verification, the name check went with
it. It does not: libcurl performs hostname verification *itself*,
separately from that hook. Against the live server a **correct** pin
therefore failed with

```
CURLcode=60  SSL: no alternative certificate subject name
             matches target host name '10.0.20.199'
```

even though the callback ran and matched. The PBS self-signed certificate
carries `DNS:localhost, DNS:pbs, DNS:pbs.thirdlevelit.local` and
`IP:127.0.0.1` — not the management IP the daemon connects to.

The wrong fix is lowering `VERIFYHOST`. The fix is to give hostname
verification something true to check: the device carries
**`tls_servername`**, and when set the driver addresses the request to
that name while pinning the name to the configured address with
`CURLOPT_RESOLVE`. Both checks stay on, there is no DNS dependency, and
nothing is disabled:

```
[PBS] Connecting to https://pbs.thirdlevelit.local:8007 via 10.0.20.199
      (pinned cert, hostname verification on, 1 datastore allowlisted)
```

The general lesson for the next driver: **verify the TLS posture against a
real server before deploy.** Every unit test passed while this was broken,
because no unit test opens a socket — by design. A live probe in both
directions (correct pin connects, wrong pin refuses) is the only thing
that catches it.

Contrast `driver_wazuh.c`, which HONORS a `VIRP_WAZUH_INSECURE=1` escape
hatch for the lab manager's self-signed cert (2026-08-07: no longer shipped
in the canonical unit — it is a manual lab-only drop-in now — but the
driver still reads the env var when set). That escape hatch is precisely
the shape this driver must never grow: a boolean has a value meaning "do
not check"; a fingerprint does not.

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
PBS_SERVERNAME=pbs.example.local        # name on the cert (see below)
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
  "tls_servername": "${PBS_SERVERNAME}",
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
- **`tls_servername`** is the name the certificate is issued for, when
  that differs from `host`. Required whenever `host` is an IP the
  certificate's SAN does not cover — the normal case for a self-signed PBS
  certificate. Read it off the cert:
  `openssl s_client -connect <ip>:8007 | openssl x509 -noout -ext subjectAltName`.
  Empty means "use `host` unchanged", which is correct only when `host` is
  itself covered by the certificate.
- **`username` holds the token id, not a login.** The auth header is
  `Authorization: PBSAPIToken=<username>:<api_token>`.
- The host must not collide with the daemon's hard-exclusion list
  (`ONODE_BLOCKED_ADDRS` in `src/virp_onode.c`); a config naming a blocked
  address is refused and the daemon does not start.

## 8b. Observation size vs. the chain artifact limit — OPEN

REST bodies are large, and that collides with the chain's artifact limit
in a way CLI-shaped drivers never hit.

The daemon caps a chain artifact at **8192 bytes**. Two of the four v1 PBS
operations exceed it comfortably:

| operation | observation size | chain-registered? |
|---|---|---|
| `backup.version.read` | ~200 B | yes |
| `backup.verify.tasks` | ~400 B | yes |
| `backup.datastore.usage` | **27,841 B** | **no** |
| `backup.snapshots.list` | **>8 KB** | **no** |

The client REFUSES to register an oversized observation rather than store
it truncated:

```
chain-register: observation is 27841 bytes; its base64 body (37131)
exceeds the daemon's 8192-byte artifact limit and would be stored
truncated (unverifiable). Not registered.
```

**That refusal is correct and must not be "fixed" by truncating.** A
truncated artifact is an artifact whose hash cannot be recomputed from
the stored bytes — evidence that looks like evidence and isn't. Refusing
is the right failure.

But the consequence is real and currently unaddressed: two of the four
operations produce **signed, signature-VALID, GREEN observations that are
not in the chain at all**. In an autopilot cycle they report `chain=-`
and do not alert, which is quieter than it should be.

**The intended pattern** — already proven by the compliance-evidence
collector (`docs/RUNBOOK-EVIDENCE.md`) — is to store the artifact **out of
band** and chain-register a small record carrying the artifact's **path
and sha256** instead of its bytes. The chain then commits to the content
without holding it, and verification recomputes the hash from the stored
file.

**Status: OPEN.** Not designed for the driver path yet. Until it is, a
typed-op driver whose responses can exceed 8 KB should expect partial
chain coverage, and should say so where an operator will see it rather
than leaving a bare `chain=-`. New REST drivers must size their
observations against this limit *before* claiming chain coverage.

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

## 9a. Source layout (decision on record, 2026-07-31)

**Driver sources live in `src/drivers/`.** `driver_pbs.c` was placed there
because that is where nine of the ten existing drivers already live — it
is neither a new convention nor an accident, it is the existing majority.
`src/driver_panos.c` is the lone outlier and is left where it is; moving
it is a rename with no functional payoff and real churn against a driver
nobody was touching tonight.

Guards were audited against both locations at the time of this decision:

| guard | how it scans | covers both? |
|---|---|---|
| `lint-sprintf`, `lint-rand`, `lint-memcmp` | `grep -rn … src/` (recursive) | yes |
| `check-pbs-pin` | explicit path to the PBS sources | n/a (PBS only) |
| `check-shared-readpath` | explicit four-file list, already naming both `src/drivers/*.c` and `src/driver_panos.c` | yes |
| driver object rules | one explicit rule per source file | yes |
| `asan-drivers` | test targets → `$(LIB)` → `LIB_OBJS` | location-independent |

Two caveats worth knowing rather than rediscovering:

- `check-shared-readpath` is a **hand-maintained list**, not a glob. It
  covers both layouts today, but a new SSH driver in either location would
  be silently unguarded. Same staleness class as the deploy-unit list that
  missed six autopilot units on 2026-07-31 — worth converting to a glob
  over `src/drivers/driver_*.c src/driver_*.c` when someone next touches
  an SSH driver.
- A new driver still needs an explicit `$(BUILD_DIR)/driver_X.o` rule.
  There is no pattern rule, so a driver added without one fails to link
  rather than being silently omitted — a fine failure mode, just not an
  automatic one.

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
