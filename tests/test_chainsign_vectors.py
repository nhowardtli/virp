#!/usr/bin/env python3
"""
D-1 asymmetric tier — Python verifier cross-check (report/verify.py).

Two locks, both PUBLIC KEY ONLY:

  1. Golden vectors (tests/vectors/chain-signing-v1.json): report/verify.py's
     Ed25519 backend must verify every signature the C module produced
     (deterministic), reject each under the wrong domain tag, and reject a
     one-byte-tampered message. This proves the Python and C constructions
     agree byte-for-byte on TAG || canonical.

  2. A live signed chain: the C test binary emits a chain the real append
     path signed (VIRP_CHAINSIGN_OUT); verify.verify_chain_signatures then
     verifies it with the .pub alone, and a tampered copy must FAIL.

The Ed25519 backend is optional. If neither PyNaCl nor cryptography is
importable this test SKIPS loudly (exit 0) rather than passing silently —
the make target notes the skip.
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VECTORS = os.path.join(HERE, "vectors", "chain-signing-v1.json")
sys.path.insert(0, os.path.join(ROOT, "report"))
import verify  # noqa: E402

passed = 0
failed = 0


def check(name, ok, detail=""):
    global passed, failed
    print("  [%s] %-60s %s" % ("PASS" if ok else "FAIL", name, detail))
    if ok:
        passed += 1
    else:
        failed += 1


def test_golden_vectors():
    doc = json.load(open(VECTORS, encoding="utf-8"))
    pub = bytes.fromhex(doc["test_key"]["public_key_hex"])
    check("verify.py key_id == vector key_id",
          verify.chainsign_key_id(pub) == doc["test_key"]["key_id_hex"])
    tag_of = {"entry": verify.CHAINSIGN_TAG_ENTRY,
              "head": verify.CHAINSIGN_TAG_HEAD}
    for v in doc["vectors"]:
        tag = tag_of[v["tag"]]
        other = (verify.CHAINSIGN_TAG_HEAD if v["tag"] == "entry"
                 else verify.CHAINSIGN_TAG_ENTRY)
        msg = bytes.fromhex(v["message_hex"])
        verdict, _ = verify.chainsign_verify(pub, tag, msg, v["signature_hex"])
        check("vector %s verifies" % v["name"], verdict == verify.PASS)
        # cross-domain
        cd, _ = verify.chainsign_verify(pub, other, msg, v["signature_hex"])
        check("vector %s rejected under the other tag" % v["name"],
              cd == verify.FAIL)
        # tampered message
        bad = bytearray(msg); bad[len(bad) // 2] ^= 0x01
        tv, _ = verify.chainsign_verify(pub, tag, bytes(bad), v["signature_hex"])
        check("vector %s rejected when message tampered" % v["name"],
              tv == verify.FAIL)


def _load_db(db):
    conn = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    conn.row_factory = sqlite3.Row
    cols = verify.ENTRY_COLUMNS + ("chain_sig", "chain_sig_key_id")
    entries = [dict(r) for r in conn.execute(
        "SELECT " + ",".join(cols) +
        " FROM chain_entries ORDER BY session_id, sequence")]
    heads = {r["session_id"]: dict(r) for r in conn.execute(
        "SELECT session_id, last_sequence, last_entry_hash, head_hmac, "
        "head_sig, head_sig_key_id FROM chain_heads")}
    conn.close()
    return entries, heads


def test_live_signed_chain():
    binary = os.path.join(ROOT, "build", "test_chain_signing")
    if not os.path.exists(binary):
        check("live signed chain (build/test_chain_signing present)", False,
              "binary missing — run `make build/test_chain_signing`")
        return
    with tempfile.TemporaryDirectory(prefix="virp-cs-") as td:
        r = subprocess.run([binary], env=dict(os.environ, VIRP_CHAINSIGN_OUT=td),
                           capture_output=True, text=True)
        if r.returncode != 0:
            check("emit signed fixture", False, r.stderr[-300:])
            return
        db = os.path.join(td, "chain.db")
        pub = verify.load_chainsign_pub(os.path.join(td, "sign.pub"))
        entries, heads = _load_db(db)
        res = verify.verify_chain_signatures(entries, heads, pub)
        s = res.get("fixture-sess", {})
        check("live chain: asymmetric verify PASS (pubkey only)",
              s.get("verdict") == verify.PASS, str(s.get("detail")))
        check("live chain: all 6 entries signed+verified",
              s.get("entries_signed") == 6, str(s.get("entries_signed")))

        # Tamper one stored signature -> FAIL.
        db2 = os.path.join(td, "chain2.db")
        shutil.copy(db, db2)
        conn = sqlite3.connect(db2)
        conn.execute(
            "UPDATE chain_entries SET chain_sig="
            "  (CASE substr(chain_sig,1,1) WHEN 'a' THEN 'b' ELSE 'a' END)"
            "  || substr(chain_sig,2) "
            "WHERE sequence=(SELECT MAX(sequence) FROM chain_entries)")
        conn.commit(); conn.close()
        e2, h2 = _load_db(db2)
        res2 = verify.verify_chain_signatures(e2, h2, pub)
        check("tampered signature -> FAIL",
              res2.get("fixture-sess", {}).get("verdict") == verify.FAIL)

        # A different key -> soft key_unavailable, not FAIL.
        other_pub = _random_ed25519_pub()
        res3 = verify.verify_chain_signatures(entries, heads, other_pub)
        check("wrong key -> key_unavailable (soft)",
              res3.get("fixture-sess", {}).get("verdict") == "key_unavailable")


def _random_ed25519_pub():
    """A fresh Ed25519 public key from whichever backend is importable.
    The module docstring promises PyNaCl OR cryptography; this used to
    hard-import PyNaCl, so a cryptography-only host crashed with
    ModuleNotFoundError instead of running the cross-check."""
    try:
        from nacl.signing import SigningKey
        return bytes(SigningKey.generate().verify_key)
    except ImportError:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return Ed25519PrivateKey.generate().public_key().public_bytes_raw()


def main():
    print("\n=== D-1 asymmetric tier — Python verifier cross-check ===\n")
    if not verify.chainsign_available():
        print("  SKIP: no Ed25519 backend (pip install pynacl or cryptography)")
        print("        The C asymmetric tier is unaffected; this Python "
              "cross-check is skipped.\n")
        return 0
    print("  backend: %s\n" % verify.chainsign_backend_name())
    test_golden_vectors()
    test_live_signed_chain()
    print("\n=== Results: %d passed, %d failed ===\n" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
