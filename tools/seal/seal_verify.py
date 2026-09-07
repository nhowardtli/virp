#!/usr/bin/env python3
"""
seal_verify.py — virp-seal/1 Phase A ceremony verifier (standalone, read-only).

Reproduces the VIRP chain canonical construction from /opt/virp source at
commit 70b3013a (chain/crypto sources identical to installed a1f4bc99):

  src/virp_chain.c:899-927   build_canonical_json   (entry canonical bytes)
  src/virp_chain.c:852-870   sha256_hex / hmac_sha256_hex
  src/virp_chain.c:886-892   compute_genesis_hash   ("VIRP_CHAIN_GENESIS:" + session_id)
  src/virp_chain.c:967-992   head_canonical / head_hmac_hex ("v":"VIRP-CHAIN-HEAD-v1")
  src/virp_chain.c:1024-1058 insert_milestone canonical + HMAC
  src/virp_chain.c:549-607   strict base64 decoder + artifact digest rule
  src/virp_chain.c:1640-1675 chain_verify_binding_locked (three-way grading)
  src/virp_chain.c:1744-1852 chain_verify_locked (contiguity, link, hash, HMAC, completeness)
  src/virp_chain.c:128-218   chain_verify_session_locked (head HMAC, head == last entry)
  src/virp_crypto.c:408-414  virp_hmac_sha256 = HMAC-SHA256 with the 32-byte key
  include/virp_chain.h:31    VIRP_CHAIN_ARTIFACT_CONTENT_MAX = 8191

Modes:
  fixtures [--key PATH]                    reproduce Appendix A fixtures (HMACs only if --key)
  full --db SNAPSHOT --key PATH --out T.json --headset H.json
                                           full walk of every session in the snapshot

Key handling: the chain key is read in place, held only in process memory,
used only as HMAC input, and never printed, logged, written, or included in
any error message. The only key-derived value emitted is
chain_key_id = hex(SHA-256(key)[0:16])  ("sha256-raw-16" applied to the 32 secret bytes).
"""
import argparse, hashlib, hmac, json, os, sqlite3, sys, time, binascii

TOOL_VERSION = "seal_verify.py virp-seal/1 phase-A 2026-08-23"
GENESIS_PREFIX = b"VIRP_CHAIN_GENESIS:"
ARTIFACT_CONTENT_MAX = 8191
INDIRECT_TYPES = {"comparator_verdict", "comparator_verd", "chainwalk_summary", "chainwalk_summa"}
OBSERVATION_TYPES = {"observation", "fed_observation"}

# C buffer sizes in virp_chain_entry_t (include/virp_chain.h:38-53); snprintf "%s" truncates to size-1.
BUF = {"session_id": 64, "artifact_id": 128, "artifact_type": 16, "artifact_hash": 65,
       "artifact_hash_alg": 8, "artifact_schema_version": 8, "signer_org_id": 64,
       "previous_entry_hash": 65, "chain_entry_hash": 65, "chain_hmac": 65}


def utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def cstr(s, size):
    """Mirror snprintf(buf, size, "%s", s): UTF-8 bytes, stop at NUL, truncate to size-1."""
    b = s.encode("utf-8") if isinstance(s, str) else bytes(s)
    nul = b.find(b"\x00")
    if nul >= 0:
        b = b[:nul]
    return b[: size - 1]


def u64(v):
    """(uint64_t)sqlite3_column_int64 → %llu."""
    return v & 0xFFFFFFFFFFFFFFFF


def u32(v):
    """(uint32_t)sqlite3_column_int → %u."""
    return v & 0xFFFFFFFF


def build_canonical(e):
    """Byte-exact mirror of build_canonical_json (src/virp_chain.c:899-927)."""
    return (b'{"artifact_hash":"' + cstr(e["artifact_hash"], BUF["artifact_hash"]) +
            b'","artifact_hash_alg":"' + cstr(e["artifact_hash_alg"], BUF["artifact_hash_alg"]) +
            b'","artifact_id":"' + cstr(e["artifact_id"], BUF["artifact_id"]) +
            b'","artifact_schema_version":"' + cstr(e["artifact_schema_version"], BUF["artifact_schema_version"]) +
            b'","artifact_type":"' + cstr(e["artifact_type"], BUF["artifact_type"]) +
            b'","monotonic_ns":' + str(u64(e["monotonic_ns"])).encode() +
            b',"previous_entry_hash":"' + cstr(e["previous_entry_hash"], BUF["previous_entry_hash"]) +
            b'","sequence":' + str(int(e["sequence"])).encode() +
            b',"session_id":"' + cstr(e["session_id"], BUF["session_id"]) +
            b'","signer_node_id":' + str(u32(e["signer_node_id"])).encode() +
            b',"signer_org_id":"' + cstr(e["signer_org_id"], BUF["signer_org_id"]) +
            b'","timestamp_ns":' + str(u64(e["timestamp_ns"])).encode() + b"}")


def head_canonical(session_id, last_sequence, last_entry_hash):
    """Mirror head_canonical (src/virp_chain.c:967-980)."""
    return (b'{"last_entry_hash":"' + cstr(last_entry_hash, 65) +
            b'","last_sequence":' + str(int(last_sequence)).encode() +
            b',"session_id":"' + cstr(session_id, 64) +
            b'","v":"VIRP-CHAIN-HEAD-v1"}')


def milestone_canonical(session_id, sequence, entries_covered, cumulative_hash):
    """Mirror insert_milestone canonical (src/virp_chain.c:1033-1040)."""
    return (b'{"cumulative_hash":"' + cstr(cumulative_hash, 65) +
            b'","entries_covered":' + str(int(entries_covered)).encode() +
            b',"sequence":' + str(int(sequence)).encode() +
            b',"session_id":"' + cstr(session_id, 64) + b'"}')


def genesis_hash(session_id):
    """Mirror compute_genesis_hash (src/virp_chain.c:886-892)."""
    return hashlib.sha256(GENESIS_PREFIX + cstr(session_id, 64)).hexdigest()


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def hmac_hex(key, b):
    return hmac.new(key, b, hashlib.sha256).hexdigest()


def hexeq(a, b):
    """Mirror hexdigest_eq: equal length and constant-time equal."""
    if a is None or b is None or len(a) != len(b):
        return False
    return hmac.compare_digest(a.encode(), b.encode())


# ---- strict base64 + artifact digest (src/virp_chain.c:549-607) ----------------
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64V = {c: i for i, c in enumerate(_B64)}


def strict_b64_decode(s):
    """Returns bytes or None (the C decoder's -1)."""
    n = len(s)
    if n % 4 != 0:
        return None
    out = bytearray()
    for i in range(0, n, 4):
        v = [0, 0, 0, 0]
        pad = 0
        for k in range(4):
            c = s[i + k]
            if c == "=":
                if i + 4 != n or k < 2:
                    return None
                v[k] = 0
                pad += 1
            else:
                if pad:
                    return None
                val = _B64V.get(c)
                if val is None:
                    return None
                v[k] = val
        trip = (v[0] << 18) | (v[1] << 12) | (v[2] << 6) | v[3]
        want = 3 - pad
        for k in range(want):
            out.append((trip >> (16 - 8 * k)) & 0xFF)
    return bytes(out)


def artifact_bytes(content):
    """The exact bytes virp_chain_artifact_digest hashes, or None if undecodable."""
    b = content.encode("utf-8")
    nul = b.find(b"\x00")
    if nul >= 0:
        b = b[:nul]
    if b.startswith(b"base64:"):
        s = b[7:].decode("ascii", errors="replace")
        return strict_b64_decode(s)
    return b


def grade_binding(artifact_type, body):
    """Mirror chain_verify_binding_locked: 1 bound, 0 unverifiable, -1 broken.
    body is the stored artifact_content for (artifact_id, artifact_hash), or None."""
    if body is None:
        return 0, None
    b = body.encode("utf-8")
    nul = b.find(b"\x00")
    blen = nul if nul >= 0 else len(b)
    if blen == 0:
        return 0, None
    if blen >= ARTIFACT_CONTENT_MAX:
        return 0, "truncated"
    if artifact_type in INDIRECT_TYPES:
        return 0, "indirect"
    raw = artifact_bytes(body)
    if raw is None:
        return -1, "undecodable"
    return 1, raw


# ---- key -----------------------------------------------------------------------
def load_key(path):
    """Read the 32-byte chain key in place. Never echo bytes."""
    try:
        st = os.stat(path)
    except OSError as ex:
        raise SystemExit("key file not accessible (%s)" % ex.strerror)
    if st.st_size != 32:
        raise SystemExit("key file size is %d, expected 32 — refusing" % st.st_size)
    with open(path, "rb") as f:
        k = f.read(32)
    if len(k) != 32:
        raise SystemExit("key file short read — refusing")
    key_id = hashlib.sha256(k).hexdigest()[:32]
    return k, key_id


# ---- fixtures ------------------------------------------------------------------
def run_fixtures(fixture_path, key):
    fx = json.load(open(fixture_path, encoding="utf-8"))
    results = []

    def rec(name, ok, detail=""):
        results.append({"check": name, "ok": bool(ok), "detail": detail})
        print("  [%s] %s %s" % ("PASS" if ok else "FAIL", name, detail))

    ents = fx["entries"]
    for fid in sorted(ents):
        e = ents[fid]
        fields = json.loads(e["canonical_utf8"])
        expect = e["canonical_utf8"].encode("utf-8")
        got = build_canonical(fields)
        print("fixture %s — %s seq %d" % (fid, e["session_id"], e["sequence"]))
        rec("%s canonical bytes == Appendix utf8" % fid, got == expect, "%d bytes" % len(got))
        rec("%s canonical_len" % fid, len(got) == e["canonical_len"], "%d" % len(got))
        if e.get("canonical_hex"):
            rec("%s canonical bytes == Appendix hex dump" % fid, got == bytes.fromhex(e["canonical_hex"]))
        else:
            rec("%s canonical hex dump" % fid, True, "(none in Appendix; utf8 only)")
        h = sha256_hex(got)
        rec("%s sha256(canonical) == chain_entry_hash" % fid, hexeq(h, e["chain_entry_hash"]), h)
        rec("%s fields session/seq match header" % fid,
            fields["session_id"] == e["session_id"] and fields["sequence"] == e["sequence"])
        if key is not None:
            m = hmac_hex(key, got)
            rec("%s HMAC-SHA256(K_chain, canonical) == chain_hmac" % fid, hexeq(m, e["chain_hmac"]), m)
        else:
            rec("%s HMAC" % fid, True, "(skipped: no key in this mode)")
        if e.get("artifact_content"):
            body = e["artifact_content"]
            rec("%s literal body length" % fid, len(body.encode()) == e["artifact_content_len"], "%d B" % len(body.encode()))
            g, raw = grade_binding(fields["artifact_type"], body)
            bh = sha256_hex(raw) if g == 1 else None
            rec("%s sha256(literal body) == artifact_hash" % fid,
                g == 1 and hexeq(bh, fields["artifact_hash"]) and hexeq(bh, e["artifact_hash_of_body"]), bh or "")
        if e.get("decoded_hex"):
            raw = bytes.fromhex(e["decoded_hex"])
            rec("%s sha256(decoded body) == artifact_hash" % fid, hexeq(sha256_hex(raw), fields["artifact_hash"]), "%d B" % len(raw))
            rec("%s v1 header: version=1 type=1 length==len" % fid,
                raw[0] == 1 and raw[1] == 1 and int.from_bytes(raw[2:4], "big") == len(raw),
                "len field %d" % int.from_bytes(raw[2:4], "big"))
            rec("%s v1 sub-header obs_length + 60 == len" % fid, int.from_bytes(raw[58:60], "big") + 60 == len(raw))
            b64 = "base64:" + binascii.b2a_base64(raw, newline=False).decode()
            g, raw2 = grade_binding("observation", b64)
            rec("%s strict base64 round-trip via binding grader" % fid, g == 1 and raw2 == raw)
    # link rule across B/C/D
    B, C, D = ents["B"], ents["C"], ents["D"]
    rec("link: C.previous_entry_hash == B.chain_entry_hash",
        json.loads(C["canonical_utf8"])["previous_entry_hash"] == B["chain_entry_hash"])
    rec("link: B.previous_entry_hash == D.chain_entry_hash",
        json.loads(B["canonical_utf8"])["previous_entry_hash"] == D["chain_entry_hash"])
    # genesis
    A = json.loads(ents["A"]["canonical_utf8"])
    rec("genesis: A.previous_entry_hash == sha256(VIRP_CHAIN_GENESIS:autopilot:2026-08-22)",
        A["previous_entry_hash"] == genesis_hash("autopilot:2026-08-22"), genesis_hash("autopilot:2026-08-22"))
    for g in fx["genesis"]:
        if g.get("genesis_hash"):
            rec("genesis: sha256(VIRP_CHAIN_GENESIS:%s)" % g["session_id"],
                genesis_hash(g["session_id"]) == g["genesis_hash"], genesis_hash(g["session_id"]))
    # head
    hd = fx["head"]
    hc = head_canonical(hd["session_id"], hd["last_sequence"], hd["last_entry_hash"])
    rec("head canonical == Appendix utf8", hc == hd["canonical_utf8"].encode())
    rec("head canonical == Appendix hex dump", hc == bytes.fromhex(hd["canonical_hex"]))
    if key is not None:
        m = hmac_hex(key, hc)
        rec("head HMAC-SHA256(K_chain, head canonical) == head_hmac", hexeq(m, hd["head_hmac"]), m)
    else:
        rec("head HMAC", True, "(skipped: no key in this mode)")
    # milestone
    ms = fx["milestone"]
    mc = milestone_canonical(ms["session_id"], ms["sequence"], ms["entries_covered"], ms["cumulative_hash"])
    rec("milestone canonical == Appendix utf8", mc == ms["canonical_utf8"].encode())
    if key is not None:
        m = hmac_hex(key, mc)
        rec("milestone HMAC-SHA256(K_chain, canonical) == chain_hmac", hexeq(m, ms["chain_hmac"]), m)
    else:
        rec("milestone HMAC", True, "(skipped: no key in this mode)")
    # strict decoder negatives
    for bad in ["abc", "=abc", "ab=c", "ab==cd", "a=bc", "abc$"]:
        rec("strict base64 rejects %r" % bad, strict_b64_decode(bad) is None)
    rec("strict base64 accepts 'YWI=' -> b'ab'", strict_b64_decode("YWI=") == b"ab")
    ok = all(r["ok"] for r in results)
    return ok, results


# ---- full walk -----------------------------------------------------------------
ENTRY_COLS = ("session_id", "sequence", "chain_entry_hash", "previous_entry_hash", "timestamp_ns",
              "monotonic_ns", "artifact_type", "artifact_id", "artifact_hash", "artifact_hash_alg",
              "artifact_schema_version", "signer_node_id", "signer_org_id", "chain_hmac", "id")


def give_back(*paths):
    """When run via sudo, hand output files to the invoking user (SUDO_UID/SUDO_GID), mode 0644."""
    if os.geteuid() == 0 and os.environ.get("SUDO_UID"):
        uid, gid = int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", os.environ["SUDO_UID"]))
        for p in paths:
            try:
                os.chown(p, uid, gid)
                os.chmod(p, 0o644)
            except OSError as ex:
                print("warning: could not chown %s: %s" % (p, ex.strerror), file=sys.stderr)


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run_full(db_path, key, key_id, out_path, headset_path, fixture_path, in_flight_window_s):
    started = utcnow()
    transcript = {"tool": TOOL_VERSION, "tool_sha256": file_sha256(os.path.abspath(__file__)),
                  "db_path": os.path.abspath(db_path), "db_sha256_before": file_sha256(db_path),
                  "started_at": started, "chain_key_id": key_id,
                  "chain_key_id_scheme": "sha256-raw-16 over the 32 secret bytes: hex(SHA-256(K_chain)[0:16]); "
                                         "truncation of hmac-key-fingerprint/1 = hex(SHA-256(secret)); not a public key id",
                  "status": "RUNNING"}
    # Fixture pre-flight with key (gate 6, HMAC half)
    print("== fixture pre-flight (with key) ==")
    fok, fres = run_fixtures(fixture_path, key)
    transcript["fixtures_with_key"] = {"all_ok": fok, "checks": len(fres), "failed": [r for r in fres if not r["ok"]]}
    if not fok:
        transcript["status"] = "HALTED_FIXTURE_GATE"
        transcript["finished_at"] = utcnow()
        json.dump(transcript, open(out_path, "w"), indent=1, sort_keys=True)
        give_back(out_path)
        print("FIXTURE GATE FAILED — ceremony halted")
        return 2

    uri = "file:%s?mode=ro" % os.path.abspath(db_path)
    con = sqlite3.connect(uri, uri=True)
    con.text_factory = str
    cur = con.cursor()
    # schema sanity
    tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for t in ("chain_entries", "chain_heads", "artifacts", "chain_milestones"):
        if t not in tables:
            raise SystemExit("snapshot missing table %s" % t)
    entries_total = cur.execute("SELECT COUNT(*) FROM chain_entries").fetchone()[0]
    heads_total = cur.execute("SELECT COUNT(*) FROM chain_heads").fetchone()[0]
    sessions_entries = [r[0] for r in cur.execute("SELECT DISTINCT session_id FROM chain_entries ORDER BY session_id")]
    sessions_heads = [r[0] for r in cur.execute("SELECT session_id FROM chain_heads ORDER BY session_id")]
    max_id_row = cur.execute("SELECT id, session_id, sequence, chain_entry_hash FROM chain_entries ORDER BY id DESC LIMIT 1").fetchone()
    print("snapshot: %d entries, %d sessions with entries, %d head rows" % (entries_total, len(sessions_entries), heads_total))
    transcript["snapshot_counts"] = {"entries": entries_total, "sessions_with_entries": len(sessions_entries), "head_rows": heads_total,
                                     "artifacts_rows": cur.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0],
                                     "milestone_rows": cur.execute("SELECT COUNT(*) FROM chain_milestones").fetchone()[0],
                                     "intent_rows": cur.execute("SELECT COUNT(*) FROM intents").fetchone()[0] if "intents" in tables else None}
    mismatches = []
    if set(sessions_entries) != set(sessions_heads):
        mismatches.append({"kind": "session_set", "entries_only": sorted(set(sessions_entries) - set(sessions_heads)),
                           "heads_only": sorted(set(sessions_heads) - set(sessions_entries))})

    counters = {"entries_walked": 0, "hash_ok": 0, "link_ok": 0, "genesis_ok": 0, "hmac_ok": 0,
                "heads_hmac_ok": 0, "heads_match_last_entry_ok": 0, "heads_count_ok": 0,
                "binding_bound": 0, "binding_unverifiable": 0, "binding_broken": 0,
                "unverifiable_reason": {"no_body_row": 0, "empty_body": 0, "truncated": 0, "indirect": 0}}
    body_census = {"observation_bodies_by_version_byte": {}, "retained_bodies_total": 0,
                   "retained_base64_bodies": 0, "retained_literal_bodies": 0}
    by_type = {}
    v2_entries, v3_entries, other_version_entries = [], [], []
    sessions_out = []
    art_stmt = "SELECT artifact_content FROM artifacts WHERE artifact_id = ? AND artifact_hash = ?"
    acur = con.cursor()
    t0 = time.time()

    for si, sid in enumerate(sessions_entries):
        rows = cur.execute("SELECT %s FROM chain_entries WHERE session_id = ? ORDER BY sequence" % ",".join(ENTRY_COLS), (sid,))
        expected_seq = 0
        expected_prev = genesis_hash(sid)
        n = 0
        last_hash = None
        first_ts = last_ts = None
        for row in rows:
            e = dict(zip(ENTRY_COLS, row))
            seq = e["sequence"]
            fail = None
            if seq != expected_seq:
                fail = "sequence gap: expected %d got %d" % (expected_seq, seq)
            elif e["previous_entry_hash"] != expected_prev:
                fail = "previous_entry_hash mismatch" + (" (genesis)" if seq == 0 else "")
            if fail is None:
                canon = build_canonical(e)
                h = sha256_hex(canon)
                if not hexeq(h, e["chain_entry_hash"]):
                    fail = "entry hash mismatch (recomputed %s)" % h
                else:
                    counters["hash_ok"] += 1
                    m = hmac_hex(key, canon)
                    if not hexeq(m, e["chain_hmac"]):
                        fail = "chain HMAC mismatch"
                    else:
                        counters["hmac_ok"] += 1
            if fail:
                mismatches.append({"kind": "entry", "session_id": sid, "sequence": seq,
                                   "chain_entry_hash": e["chain_entry_hash"], "detail": fail})
                break
            counters["link_ok"] += 1
            if seq == 0:
                counters["genesis_ok"] += 1
            # artifact binding (three-way) + census
            arow = acur.execute(art_stmt, (e["artifact_id"], e["artifact_hash"])).fetchone()
            body = arow[0] if arow else None
            g, raw = grade_binding(e["artifact_type"], body)
            if g == 1:
                if hexeq(sha256_hex(raw), e["artifact_hash"]):
                    counters["binding_bound"] += 1
                else:
                    g = -1
                    raw = "hash-mismatch"
            if g == 0:
                counters["binding_unverifiable"] += 1
                if body is None:
                    counters["unverifiable_reason"]["no_body_row"] += 1
                elif raw is None:
                    counters["unverifiable_reason"]["empty_body"] += 1
                else:
                    counters["unverifiable_reason"][raw] += 1
            elif g == -1:
                counters["binding_broken"] += 1
                mismatches.append({"kind": "artifact_binding_broken", "session_id": sid, "sequence": seq,
                                   "chain_entry_hash": e["chain_entry_hash"], "detail": str(raw)})
                break
            if body is not None and len(body) > 0:
                body_census["retained_bodies_total"] += 1
                if body.startswith("base64:"):
                    body_census["retained_base64_bodies"] += 1
                else:
                    body_census["retained_literal_bodies"] += 1
                if e["artifact_type"] in OBSERVATION_TYPES:
                    rb = artifact_bytes(body)
                    vb = ("0x%02x" % rb[0]) if rb else "undecodable"
                    body_census["observation_bodies_by_version_byte"][vb] = body_census["observation_bodies_by_version_byte"].get(vb, 0) + 1
                    ref = {"session_id": sid, "sequence": seq, "chain_entry_hash": e["chain_entry_hash"], "body_len": len(rb) if rb else None}
                    if rb and rb[0] == 2:
                        v2_entries.append(ref)
                    elif rb and rb[0] == 3:
                        v3_entries.append(ref)
                    elif not rb or rb[0] != 1:
                        other_version_entries.append(ref)
            by_type[e["artifact_type"]] = by_type.get(e["artifact_type"], 0) + 1
            expected_prev = e["chain_entry_hash"]
            expected_seq += 1
            n += 1
            last_hash = e["chain_entry_hash"]
            ts = u64(e["timestamp_ns"])
            first_ts = ts if first_ts is None else first_ts
            last_ts = ts
            counters["entries_walked"] += 1
        if mismatches:
            break
        # head record (chain_verify_session_locked)
        hrow = cur.execute("SELECT last_sequence, last_entry_hash, head_hmac, updated_at_ns FROM chain_heads WHERE session_id = ?", (sid,)).fetchone()
        if hrow is None:
            mismatches.append({"kind": "head_missing", "session_id": sid, "sequence": n - 1, "chain_entry_hash": last_hash})
            break
        hseq, hhash, hmac_stored, hupd = hrow
        hc = head_canonical(sid, hseq, hhash)
        if not hexeq(hmac_hex(key, hc), hmac_stored):
            mismatches.append({"kind": "head_hmac", "session_id": sid, "sequence": hseq, "chain_entry_hash": hhash, "detail": "head record HMAC mismatch"})
            break
        counters["heads_hmac_ok"] += 1
        if hseq != n - 1 or hhash != last_hash:
            mismatches.append({"kind": "head_vs_entries", "session_id": sid, "sequence": hseq, "chain_entry_hash": hhash,
                               "detail": "head (%d,%s) != last walked (%d,%s)" % (hseq, hhash[:16], n - 1, (last_hash or "")[:16])})
            break
        counters["heads_match_last_entry_ok"] += 1
        counters["heads_count_ok"] += 1  # n == hseq+1 by the two checks above (contiguity from 0 + head==last)
        sessions_out.append({"session_id": sid, "entry_count": n, "head_hash": last_hash, "head_sequence": hseq,
                             "head_updated_at_ns": hupd, "first_timestamp_ns": first_ts, "last_timestamp_ns": last_ts})
        if (si + 1) % 10 == 0 or si + 1 == len(sessions_entries):
            print("  [%3d/%d] %-54s %7d entries  ok  (%d walked, %.0fs)" % (si + 1, len(sessions_entries), sid, n, counters["entries_walked"], time.time() - t0))
        sys.stdout.flush()

    transcript["finished_at"] = utcnow()
    transcript["db_sha256_after"] = file_sha256(db_path)
    transcript["mismatches"] = mismatches
    transcript["counters"] = counters
    transcript["entries_by_artifact_type"] = dict(sorted(by_type.items()))
    transcript["body_layer"] = dict(body_census, v2_entries=v2_entries, v3_entries=v3_entries, other_version_entries=other_version_entries)
    transcript["sessions_verified"] = len(sessions_out)
    transcript["last_inserted_entry"] = {"id": max_id_row[0], "session_id": max_id_row[1], "sequence": max_id_row[2], "chain_entry_hash": max_id_row[3]} if max_id_row else None
    if mismatches or counters["entries_walked"] != entries_total or len(sessions_out) != len(sessions_entries):
        transcript["status"] = "HALTED_MISMATCH"
        json.dump(transcript, open(out_path, "w"), indent=1, sort_keys=True)
        give_back(out_path)
        print("MISMATCH — ceremony halted. First failing record:")
        print(json.dumps(mismatches[0] if mismatches else {"walked": counters["entries_walked"], "total": entries_total}, indent=1))
        return 2
    if transcript["db_sha256_before"] != transcript["db_sha256_after"]:
        transcript["status"] = "HALTED_SNAPSHOT_CHANGED"
        json.dump(transcript, open(out_path, "w"), indent=1, sort_keys=True)
        give_back(out_path)
        print("snapshot sha256 changed during verification — halted")
        return 2
    transcript["status"] = "OK"
    transcript["summary"] = {
        "entries_total": entries_total, "sessions": len(sessions_out),
        "chain_layer": {"hashes_recomputed_ok": counters["hash_ok"], "links_ok": counters["link_ok"], "genesis_ok": counters["genesis_ok"],
                        "hmac_verified_ok": counters["hmac_ok"], "heads_hmac_ok": counters["heads_hmac_ok"],
                        "heads_match_last_entry_ok": counters["heads_match_last_entry_ok"], "mismatches": 0},
        "body_layer": {"v1_entries": entries_total - len(v2_entries) - len(v3_entries), "v2_entries": len(v2_entries), "v3_entries": len(v3_entries),
                       "v2_unverifiable_at_rest": len(v2_entries),
                       "artifacts_bound": counters["binding_bound"], "artifacts_unverifiable": counters["binding_unverifiable"],
                       "artifacts_broken": counters["binding_broken"]}}
    # headset
    # In-flight rule: the daemon keeps several sessions open concurrently (perpetual gate-enforce:* sessions,
    # date-scoped autopilot* sessions). A session is flagged in_flight if its head was updated within
    # in_flight_window_s before the snapshot's most recent append; those sessions are sealed at their
    # snapshot head and may legitimately grow afterwards. Every other session is sealed at its final head.
    newest_upd = max(s["head_updated_at_ns"] for s in sessions_out) if sessions_out else 0
    cutoff = newest_upd - in_flight_window_s * 1_000_000_000
    in_flight = sorted(s["session_id"] for s in sessions_out if s["head_updated_at_ns"] >= cutoff)
    headset = {"headset_version": "virp-seal/1", "snapshot_path": os.path.abspath(db_path), "snapshot_sha256": transcript["db_sha256_before"],
               "extracted_at": transcript["finished_at"], "sessions_total": len(sessions_out), "entries_total": entries_total,
               "in_flight_rule": "A session is flagged in_flight when its chain_heads.updated_at_ns lies within %d seconds before the newest head update in the snapshot (newest_head_updated_at_ns=%d, cutoff_ns=%d). In-flight sessions are sealed at their head as of the snapshot and may grow afterwards; all other sessions are sealed at their final head." % (in_flight_window_s, newest_upd, cutoff),
               "in_flight_sessions": in_flight, "sessions": []}
    for s in sorted(sessions_out, key=lambda x: x["session_id"]):
        rec = {"session_id": s["session_id"], "entry_count": s["entry_count"], "head_hash": s["head_hash"]}
        if s["session_id"] in in_flight:
            rec["in_flight"] = True
        headset["sessions"].append(rec)
    transcript["in_flight_sessions"] = in_flight
    transcript["sessions"] = sorted(sessions_out, key=lambda x: x["session_id"])
    json.dump(transcript, open(out_path, "w"), indent=1, sort_keys=True)
    json.dump(headset, open(headset_path, "w"), indent=1, sort_keys=True)
    give_back(out_path, headset_path)
    print("OK: %d entries in %d sessions; hash_ok=%d hmac_ok=%d heads_ok=%d v2=%d bound=%d unverifiable=%d broken=%d" % (
        entries_total, len(sessions_out), counters["hash_ok"], counters["hmac_ok"], counters["heads_hmac_ok"], len(v2_entries),
        counters["binding_bound"], counters["binding_unverifiable"], counters["binding_broken"]))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)
    f = sub.add_parser("fixtures")
    f.add_argument("--fixtures", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures-appendix-a.json"))
    f.add_argument("--key", default=None)
    f.add_argument("--out", default=None)
    g = sub.add_parser("full")
    g.add_argument("--db", required=True)
    g.add_argument("--key", required=True)
    g.add_argument("--out", required=True)
    g.add_argument("--headset", required=True)
    g.add_argument("--fixtures", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures-appendix-a.json"))
    g.add_argument("--in-flight-window-hours", type=float, default=24.0)
    a = ap.parse_args()
    key = key_id = None
    try:
        if a.key:
            key, key_id = load_key(a.key)
            print("chain key loaded in place; chain_key_id (sha256-raw-16) = %s" % key_id)
        if a.mode == "fixtures":
            ok, res = run_fixtures(a.fixtures, key)
            print("FIXTURE GATE: %s (%d checks, %d failed)" % ("PASS" if ok else "FAIL", len(res), sum(1 for r in res if not r["ok"])))
            if a.out:
                json.dump({"tool": TOOL_VERSION, "tool_sha256": file_sha256(os.path.abspath(__file__)), "at": utcnow(),
                           "with_key": key is not None, "chain_key_id": key_id, "all_ok": ok, "checks": res},
                          open(a.out, "w"), indent=1, sort_keys=True)
            return 0 if ok else 2
        return run_full(a.db, key, key_id, a.out, a.headset, a.fixtures, a.in_flight_window_hours * 3600)
    finally:
        if key is not None:
            try:
                key = None  # best effort; Python cannot reliably zero immutable bytes
            except Exception:
                pass


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as ex:  # never let a traceback carry unexpected state
        print("ERROR: %s: %s" % (type(ex).__name__, str(ex)[:300]), file=sys.stderr)
        sys.exit(3)
