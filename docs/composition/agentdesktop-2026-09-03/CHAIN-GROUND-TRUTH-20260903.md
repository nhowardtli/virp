# VIRP chain ground truth — 10.0.10.211, 2026-09-03T19:37:44Z

Read-only dump of `/var/lib/virp/chain.db` on the colo O-Node
(10.0.10.211). Nothing was written and the daemon was not restarted.
Produced for the Sep 3 2026 request/outcome-pair write-up.

Every value below comes from the database. `hash ok` is
`sha256(artifact body) == chain_entries.artifact_hash`, recomputed here;
`link ok` is `previous_entry_hash == chain_entry_hash` of the preceding
sequence in the same session. The chain HMAC is NOT checked here — it is
keyed under `/etc/virp/keys/chain.key`, which this reader deliberately
cannot open. Read these as structural verification, not signature
verification.

## `ncfed-unknown-unknown` — seq 330–340

| seq | type | timestamp (UTC) | device | command / payload | tier | outcome | bridge_instance | provenance_source | body schema | hash ok |
|---:|---|---|---|---|---|---|---|---|---|---|
| 330 | fed_observation | 2026-09-02T03:17:12.983670Z | — | ERROR: tier gate blocked 'gate.classifier.status' on 'zamma… | RED | OBS_ERROR | — | — | signed observation (v1) | YES |
| 331 | fed_outcome | 2026-09-02T03:17:13.026492Z | zammad-ro | gate.classifier.status | RED | refused | — | claimed | federated_outcome/1 | YES |
| 332 | fed_request | 2026-09-03T16:40:33.884904Z | clab-frr-ospf-frr1 | vtysh -c "show ipv6 ospf6 neighbor" | — | — | — | claimed | federated_request/1 | YES |
| 333 | fed_observation | 2026-09-03T16:40:34.072658Z | — | clab-frr-ospf-frr1$ vtysh -c "show ipv6 ospf6 neighbor" osp… | GREEN | obs_type=7 | — | — | signed observation (v1) | YES |
| 334 | fed_outcome | 2026-09-03T16:40:34.402485Z | clab-frr-ospf-frr1 | vtysh -c "show ipv6 ospf6 neighbor" | GREEN | executed | — | claimed | federated_outcome/1 | YES |
| 335 | fed_request | 2026-09-03T16:41:16.361243Z | clab-frr-ospf-frr1 | vtysh -c "show running-config" | — | — | — | claimed | federated_request/1 | YES |
| 336 | fed_observation | 2026-09-03T16:41:16.451696Z | — | ERROR: tier gate blocked 'vtysh -c "show running-config"' o… | YELLOW | OBS_ERROR | — | — | signed observation (v1) | YES |
| 337 | fed_outcome | 2026-09-03T16:41:16.681274Z | clab-frr-ospf-frr1 | vtysh -c "show running-config" | YELLOW | refused | — | claimed | federated_outcome/1 | YES |
| 338 | fed_request | 2026-09-03T16:41:58.384790Z | clab-frr-ospf-frr1 | configure terminal | — | — | — | claimed | federated_request/1 | YES |
| 339 | fed_observation | 2026-09-03T16:41:58.433567Z | — | ERROR: tier gate blocked 'configure terminal' on 'clab-frr-… | RED | OBS_ERROR | — | — | signed observation (v1) | YES |
| 340 | fed_outcome | 2026-09-03T16:41:58.659165Z | clab-frr-ospf-frr1 | configure terminal | RED | refused | — | claimed | federated_outcome/1 | YES |

**Link verification**

- all 11 entries link to their predecessor: OK
- every retained body hashes to its committed `artifact_hash`: OK

## `ncfed-unknown-unknown` — seq 377–379

| seq | type | timestamp (UTC) | device | command / payload | tier | outcome | bridge_instance | provenance_source | body schema | hash ok |
|---:|---|---|---|---|---|---|---|---|---|---|
| 377 | fed_request | 2026-09-03T17:54:30.354142Z | clab-frr-ospf-frr1 | vtysh -c "show ip ospf neighbor" | — | — | — | claimed | federated_request/1 | YES |
| 378 | fed_observation | 2026-09-03T17:54:30.543055Z | — | clab-frr-ospf-frr1$ vtysh -c "show ip ospf neighbor"  Neigh… | GREEN | obs_type=7 | — | — | signed observation (v1) | YES |
| 379 | fed_outcome | 2026-09-03T17:54:30.792790Z | clab-frr-ospf-frr1 | vtysh -c "show ip ospf neighbor" | GREEN | executed | — | claimed | federated_outcome/1 | YES |

**Link verification**

- all 3 entries link to their predecessor: OK
- every retained body hashes to its committed `artifact_hash`: OK

## `ncfed-user-session-req-001` — seq 0–2

| seq | type | timestamp (UTC) | device | command / payload | tier | outcome | bridge_instance | provenance_source | body schema | hash ok |
|---:|---|---|---|---|---|---|---|---|---|---|
| 0 | fed_request | 2026-09-03T17:56:31.841002Z | clab-frr-ospf-frr1 | vtysh -c "show ip ospf neighbor" | — | — | — | claimed | federated_request/1 | YES |
| 1 | fed_observation | 2026-09-03T17:56:32.032903Z | — | clab-frr-ospf-frr1$ vtysh -c "show ip ospf neighbor"  Neigh… | GREEN | obs_type=7 | — | — | signed observation (v1) | YES |
| 2 | fed_outcome | 2026-09-03T17:56:32.355429Z | clab-frr-ospf-frr1 | vtysh -c "show ip ospf neighbor" | GREEN | executed | — | claimed | federated_outcome/1 | YES |

**Link verification**

- seq 0 is the first entry examined; its `previous_entry_hash` is `aff745b96ddc176e…`.
- all 3 entries link to their predecessor: OK
- every retained body hashes to its committed `artifact_hash`: OK

## `ncfed-nhoward-netclaw` — seq 0 → head

| seq | type | timestamp (UTC) | device | command / payload | tier | outcome | bridge_instance | provenance_source | body schema | hash ok |
|---:|---|---|---|---|---|---|---|---|---|---|
| 0 | fed_request | 2026-09-03T18:46:42.923643Z | clab-frr-ospf-frr1 | vtysh -c "show ip ospf neighbor" | — | — | — | authenticated | federated_request/1 | YES |
| 1 | fed_observation | 2026-09-03T18:46:43.115640Z | — | clab-frr-ospf-frr1$ vtysh -c "show ip ospf neighbor"  Neigh… | GREEN | obs_type=7 | — | — | signed observation (v1) | YES |
| 2 | fed_outcome | 2026-09-03T18:46:43.390722Z | clab-frr-ospf-frr1 | vtysh -c "show ip ospf neighbor" | GREEN | executed | — | authenticated | federated_outcome/1 | YES |
| 3 | fed_request | 2026-09-03T18:46:59.910856Z | clab-frr-ospf-frr1 | vtysh -c "show ip ospf neighbor" | — | — | — | authenticated | federated_request/1 | YES |
| 4 | fed_observation | 2026-09-03T18:47:00.057741Z | — | clab-frr-ospf-frr1$ vtysh -c "show ip ospf neighbor"  Neigh… | GREEN | obs_type=7 | — | — | signed observation (v1) | YES |
| 5 | fed_outcome | 2026-09-03T18:47:00.310751Z | clab-frr-ospf-frr1 | vtysh -c "show ip ospf neighbor" | GREEN | executed | — | authenticated | federated_outcome/1 | YES |
| 6 | fed_request | 2026-09-03T18:47:31.614985Z | clab-frr-ospf-frr1 | vtysh -c "show ip ospf neighbor" | — | — | — | authenticated | federated_request/1 | YES |
| 7 | fed_observation | 2026-09-03T18:47:31.802533Z | — | clab-frr-ospf-frr1$ vtysh -c "show ip ospf neighbor"  Neigh… | GREEN | obs_type=7 | — | — | signed observation (v1) | YES |
| 8 | fed_outcome | 2026-09-03T18:47:31.993306Z | clab-frr-ospf-frr1 | vtysh -c "show ip ospf neighbor" | GREEN | executed | — | authenticated | federated_outcome/1 | YES |
| 9 | fed_request | 2026-09-03T18:55:18.231522Z | clab-frr-ospf-frr1 | vtysh -c "show ip ospf neighbor" | — | — | b-3926283-1722a4815b7f4… | authenticated | federated_request/1 | YES |
| 10 | fed_observation | 2026-09-03T18:55:18.419709Z | — | clab-frr-ospf-frr1$ vtysh -c "show ip ospf neighbor"  Neigh… | GREEN | obs_type=7 | — | — | signed observation (v1) | YES |
| 11 | fed_outcome | 2026-09-03T18:55:18.668180Z | clab-frr-ospf-frr1 | vtysh -c "show ip ospf neighbor" | GREEN | executed | b-3926283-1722a4815b7f4… | authenticated | federated_outcome/1 | YES |
| 12 | fed_request | 2026-09-03T19:09:45.259327Z | clab-frr-ospf-frr9 | show version | — | — | b-3932297-d9d4a2a588604… | authenticated | federated_request/1 | YES |
| 13 | fed_observation | 2026-09-03T19:09:45.303001Z | — | ERROR: device 'clab-frr-ospf-frr9' not found | UNCLASSIFIED | OBS_ERROR | — | — | signed observation (v1) | YES |
| 14 | fed_outcome | 2026-09-03T19:09:45.532806Z | clab-frr-ospf-frr9 | show version | UNCLASSIFIED | refused | b-3932297-d9d4a2a588604… | authenticated | federated_outcome/1 | YES |
| 15 | fed_request | 2026-09-03T19:34:12.025406Z | clab-frr-ospf-frr9 | show version | — | — | b-3942331-c70801653f0d4… | authenticated | federated_request/1 | YES |
| 16 | fed_observation | 2026-09-03T19:34:12.138218Z | — | ERROR: device 'clab-frr-ospf-frr9' not found | UNCLASSIFIED | OBS_ERROR | — | — | signed observation (v1) | YES |
| 17 | fed_outcome | 2026-09-03T19:34:12.373809Z | clab-frr-ospf-frr9 | show version | UNCLASSIFIED | refused | b-3942331-c70801653f0d4… | authenticated | federated_outcome/1 | YES |
| 18 | fed_request | 2026-09-03T19:34:19.531343Z | clab-frr-ospf-frr9 | show version | — | — | b-3942448-3499652ea3424… | authenticated | federated_request/1 | YES |
| 19 | fed_observation | 2026-09-03T19:34:19.535861Z | — | ERROR: device 'clab-frr-ospf-frr9' not found | UNCLASSIFIED | OBS_ERROR | — | — | signed observation (v1) | YES |
| 20 | fed_outcome | 2026-09-03T19:34:19.775485Z | clab-frr-ospf-frr9 | show version | UNCLASSIFIED | refused | b-3942448-3499652ea3424… | authenticated | federated_outcome/1 | YES |
| 21 | fed_request | 2026-09-03T19:34:33.728293Z | clab-frr-ospf-frr1 | vtysh -c "show ip ospf neighbor" | — | — | b-3942652-9840d459daef4… | authenticated | federated_request/1 | YES |

**Link verification**

- seq 0 is the first entry examined; its `previous_entry_hash` is `4a381b84945dda18…`.
- all 22 entries link to their predecessor: OK
- every retained body hashes to its committed `artifact_hash`: OK


---

## Step-4 read-back: the seq-13 observation body

The Sep 3 reproduction against `.211` through `virp-bridge-remote`
(`device = clab-frr-ospf-frr9`, which does not exist) landed as
**seq 12 / 13 / 14**. Reading the observation body back out of
`chain.db` read-only:

```
artifact_id      : ncfed-obs-2a1bbdfa7711115519eefb006a3a4ddd
artifact_hash    : 8423e8167680788f91f879a517104bbef4a8f4861b1abed707f96b9fd9d20223
sha256(body)     : 8423e8167680788f91f879a517104bbef4a8f4861b1abed707f96b9fd9d20223
MATCH            : True
body len         : 104 bytes
payload          : ERROR: device 'clab-frr-ospf-frr9' not found
chain_entry_hash : 61ea946ba1fef8d5e72188723b552af988aeb3e5ee5ba63472d7ea974fa55c9a
```

That hash is byte-identical to the `observation_sha256` the bridge
returned to the caller, and to the value the seq-14 `fed_outcome` cites.
The link from "a federated caller asked for this" to "here are the
signed bytes that say what happened" is intact for this exchange.

**Device-not-found is not one of the open-pair paths.** The O-Node
answers an unknown device with a *signed* `OBS_ERROR` observation
(`UNCLASSIFIED`, "device 'X' not found"), which the bridge stores and
cites like any other. Seqs 15–17 and 18–20 are the same reproduction
after the bridge fix was deployed: unchanged, still closing.

## Seq 21 — an open pair, deliberately

Seq 21 is a `fed_request` with no observation and no outcome. It is the
finding, reproduced on this chain on purpose.

It came from a probe that asked for `obs_version 2` over the remote
socket. Uid 993's action allowlist does not carry `session_hello`, so
the handshake was refused `-50`, the session-less v2 execute was refused
`-30`, and no observation was ever produced. Nothing reached a device.

The bridge then tried to close the pair with a `fed_error` body and was
refused `-50` — this node's `socket_uid_chain_append_types` policy does
not yet carry that type. GATE 5 held: with nothing stored, nothing was
cited, and no outcome was filed. The bridge said so on stderr:

```
[virp-bridge] could not close the request/outcome pair for correlation
5c39525e5d408b8d6e9418a24451df23: the fed_error body was refused (-50),
so no outcome was filed and the fed_request stands alone on the chain.
Original failure: transport -30 — the O-Node answered the execute with a
typed error; no observation was produced and nothing reached a device
```

Seq 21 closes once the daemon side (`virp` branch
`fix/close-error-pairs`: the `fed_error` type, GATE 4's second citation,
uid 993's policy row) is deployed here. Until then this is what the
defect looks like on a real chain, which is worth having recorded.

## What the ranges show

Apart from seq 21, **no incomplete request/outcome pair exists anywhere
in the examined ranges.** Every `fed_request` is followed by a
`fed_observation` and a `fed_outcome`, all bodies retained, all hashes
matching, all links intact.

Two provenance transitions are visible in `ncfed-nhoward-netclaw`:

- **seq 0–8** carry no `bridge_instance`. They predate the
  `d6ba605` deploy that added the per-process boundary to the body.
- **seq 9 onward** carry `bridge_instance`, and every entry in this
  session carries `provenance_source: authenticated` — the Sep 3
  identity fix. The older `ncfed-unknown-unknown` entries all read
  `provenance_source: claimed`, which is the pre-fix state written
  plainly into the evidence rather than papered over.

## `ncfed-user-session-req-001`

This is the session id **gpt-oss:120b invented** and the bridge signed
into evidence as if it were identity, before the Sep 3 fix made session
identity non-model-writable.

It sits on `.211`'s chain permanently, as three entries (seq 0–2), and
it is **not** an incomplete pair: it is a complete, correct,
fully-verified exchange — request, signed GREEN observation, outcome
`executed` — filed under a fabricated name. Its
`provenance_source` reads `claimed`, and its `previous_entry_hash`
(`aff745b96ddc176e…`) ties it into the global chain at the moment it was
written, so it cannot be excised without breaking every entry after it.

That is the right outcome. The chain is append-only and this is what
actually happened: a real command really ran, and the identity attached
to it was a model's invention. Deleting it would destroy the only
first-hand evidence that the defect existed and that it reached
production evidence. Keeping it means the fix has a before-and-after
that a verifier can read directly out of the chain: `claimed` on one
side of Sep 3, `authenticated` on the other.

---

# fed_error deploy — 2026-09-03 20:18:36 UTC

`.211` was moved from `f269455c` to **`dc49b748`** (branch
`deploy/fed-error-2026-09-03` = the `fed_error` commit cherry-picked onto
`f269455c`, so the production delta was that one commit alone). Installed
binary sha256 `b45ac9bb9ef29a6c9aa8d5d66ac9c5f33ee314bb5f8b61518834ef7e511d447e`.
Template `/etc/virp/devices.template.json` → `14ea5b5f3437cfb5…`; the only
policy change is uid 993 gaining `fed_error`.

`src/` and `include/` are byte-identical between `dc49b748` and `main`
(`ef60b3c`), so the running daemon is reproducible from mainline.

## Verification, before and after

|  | before (20:00Z) | after (20:30Z) |
|---|---|---|
| entries | 297,457 | 297,674 |
| sessions / heads | 414 | 414 |
| `entry_hash` FAIL | 0 | 0 |
| `link` FAIL | 0 | 0 |
| `chain_hmac` FAIL | 0 | 0 |
| `artifact_bind` FAIL | 0 | 0 |
| `first_broken_link` | None | None |
| **`failed_entries`** | **0** | **0** |

Entry counts differ only because the chain is live — autopilot writes every
two minutes. The invariants are what carry the claim, and none moved.

`failed_entries` is **0, not 1**. The Aug 6 run reported the `pbs-lab`
genesis as a failure; that entry (`virp-cli:pbs-lab` seq 0, an
`observation` whose body was never retained) is now graded UNVERIFIABLE
rather than FAIL, and sits inside the 29,721 UNVERIFIABLE `artifact_bind`
rows. The chain did not change; the verifier's grading was corrected.

Pre-deploy backup: `~/backups/chain-prefederror-20260903T200053Z.db`,
sha256 `6a97bf2dff2f26c532c7ce6546c9f2a9f374122c754c4d762bd5881e1e7c19f4`,
all five tables row-matched to live. Taken with SQLite's WAL-aware
`.backup` — there was a 114 MB un-checkpointed WAL a plain `cp` would have
dropped.

## What this task wrote to the chain

229 entries between 20:00:53Z and 20:31Z, of which 223 are ordinary
autopilot / gate-enforce / approval traffic. The six that are this
change:

| seq | type | artifact_id |
|---:|---|---|
| 22 | `fed_request` | `ncfed-req-1474f62a…` |
| 23 | `fed_error` | `ncfed-err-1474f62a…` |
| 24 | `fed_outcome` | `ncfed-out-1474f62a…` |
| 25 | `fed_request` | `ncfed-req-3dc18864…` |
| 26 | `fed_observation` | `ncfed-obs-3dc18864…` |
| 27 | `fed_outcome` | `ncfed-out-3dc18864…` |

Plus one `node-config:00000001` seq 3 at 20:18:36Z — the daemon writes a
`node_config` entry at every startup.

## Seq 21 stays open, permanently

Seq 21 is the `fed_request` with no outcome, written 2026-09-03 19:34 when
`fed_error` was still refused `-50` by this node's type policy. **The chain
is append-only, so seq 21 can never be closed retroactively** — its
correlation ends there and always will.

What the deploy fixed is the *next* one. Seq 22–24 is the identical probe
(`obs_version 2` over the remote socket; uid 993 has no `session_hello`, so
handshake `-50`, session-less v2 execute `-30`, no observation ever
produced), and it closed:

```
fed_error payload      {"error_class": "transport", "error_code": -30,
                        "message": "the O-Node answered the execute with a
                        typed error; no observation was produced and
                        nothing reached a device"}
sha256(fed_error body) 9854ef79fafe076e99144c82f68289a072cb014c4dfd9046bae47c39bee9df49
outcome.error_sha256   9854ef79fafe076e99144c82f68289a072cb014c4dfd9046bae47c39bee9df49   MATCH
observation_sha256     ABSENT
outcome                failed   executed: false
```

Seq 21 next to seq 22–24 is the before-and-after, readable straight off
the chain: the same failure, once as an open pair and once as a closed
one. That is worth more than a clean chain would have been.
