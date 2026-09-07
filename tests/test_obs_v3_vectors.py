#!/usr/bin/env python3
"""
HAM review, 2026-09-06 — item 8.

The C observation verifier accepts v1, v2 and v3. report/verify.py knew
v2-else-v1, so a v3 frame fell through to the v1 O-Key path and reported
FAIL. Anything the trusted daemon accepts as strong evidence has to be
verifiable by the public verifier, or the public verifier is not the
check it claims to be.

The vectors are minted by the C code itself (tests/test_obs_ed25519.c
under VIRP_OBS_V3_OUT) and checked here. The C side signs; the Python
side verifies; neither runs the other's crypto. A byte-flipped copy must
fail, and the frame must not verify under a different key.

The Ed25519 backend is optional. If neither PyNaCl nor cryptography is
importable this SKIPS loudly (exit 0) rather than passing silently.
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "report"))
import verify  # noqa: E402

passed = 0
failed = 0


def check(name, ok, detail=""):
    global passed, failed
    print("  [%s] %-58s %s" % ("PASS" if ok else "FAIL", name, detail))
    if ok:
        passed += 1
    else:
        failed += 1


def emit_vectors(tmpdir):
    binary = os.path.join(ROOT, "build", "test_obs_ed25519")
    if not os.path.exists(binary):
        print("  build/test_obs_ed25519 is not built; run `make "
              "test-obs-ed25519` first", file=sys.stderr)
        sys.exit(2)
    out = os.path.join(tmpdir, "obs-v3.json")
    env = dict(os.environ, VIRP_OBS_V3_OUT=out)
    subprocess.run([binary], env=env, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(out) as f:
        return json.load(f)


def main():
    print("\n=== v3 observation vectors: C mints, Python verifies "
          "(HAM item 8) ===")
    if not verify.chainsign_available():
        print("  SKIP: no Ed25519 backend (pynacl / cryptography) here")
        return 0

    with tempfile.TemporaryDirectory() as d:
        vec = emit_vectors(d)

    pub = bytes.fromhex(vec["public_key"])
    check("vectors carry an observation-signing public key", len(pub) == 32)

    other = bytes(32)

    for i, fr in enumerate(vec["frames"]):
        raw = bytes.fromhex(fr["frame"])
        cmd = fr["command"]

        v, detail = verify.classify_observation_v3(raw, pub)
        check("frame %d (%s) verifies" % (i, cmd), v == verify.PASS, detail)

        # The dispatch, not just the classifier: a caller that only ever
        # touches verify_observation_hmac must get the same answer.
        v2, _d = verify.verify_observation_hmac(raw, None, pub)
        check("frame %d reaches v3 through the version dispatch" % i,
              v2 == verify.PASS)

        # Header parses as v3 and names itself.
        hdr = verify.parse_observation_v3_header(raw)
        check("frame %d header parses as v3" % i,
              hdr is not None and hdr["version"] == 3
              and hdr["length"] == len(raw))

        # Every covered byte is covered: flip one in the header, one in
        # the payload, and one in the HMAC trailer.
        for label, off in (("header", 8),
                           ("payload", verify.OBS_V2_HEADER_SIZE + 1),
                           ("hmac trailer",
                            len(raw) - verify.OBS_V3_SIG_SIZE - 1)):
            bad = bytearray(raw)
            bad[off] ^= 0x01
            v3, _d = verify.classify_observation_v3(bytes(bad), pub)
            check("frame %d: flipped %s byte FAILS" % (i, label),
                  v3 == verify.FAIL)

        # And the signature itself.
        bad = bytearray(raw)
        bad[-1] ^= 0x01
        v4, _d = verify.classify_observation_v3(bytes(bad), pub)
        check("frame %d: flipped signature byte FAILS" % i,
              v4 == verify.FAIL)

        # Wrong key: FAIL, never PASS and never UNCHECKED.
        v5, _d = verify.classify_observation_v3(raw, other)
        check("frame %d does not verify under another key" % i,
              v5 == verify.FAIL)

        # No key at all: UNCHECKED with a reason, never a silent pass and
        # never a FAIL for being a version we could not check.
        v6, d6 = verify.classify_observation_v3(raw, None)
        check("frame %d with no key is UNCHECKED, with a reason" % i,
              v6 == verify.UNCHECKED and "public key" in d6)

        # Truncation and extension both break framing: a frame longer
        # than its declared length carries unauthenticated bytes behind a
        # valid signature, which is how splices hide.
        v7, _d = verify.classify_observation_v3(raw + b"\x00", pub)
        check("frame %d + one trailing byte FAILS" % i, v7 == verify.FAIL)
        v8, _d = verify.classify_observation_v3(raw[:-1], pub)
        check("frame %d truncated by one byte FAILS" % i, v8 == verify.FAIL)

    # Item 8b: what the daemon emits by default. The execute path bounds
    # obs_version at 2, so a client cannot ask for v3 at all. Pinned at
    # the source, so raising that bound has to change this test and
    # somebody has to think about it.
    onode = open(os.path.join(ROOT, "src", "virp_onode.c")).read()
    check("the execute path still bounds obs_version at 2",
          'json_extract_u64_bounded(root, "obs_version", 2, &v)' in onode)
    check("the default obs_version is still 1",
          "req->obs_version = 1;" in onode)

    print("\n=== Results: %d passed, %d failed ===" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
