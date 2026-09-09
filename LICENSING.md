# Current license boundaries and historical permissions

The current policy is proprietary except for the Apache-2.0 core: src/ (subject
to third-party exceptions), include/, proofs/, Makefile, scripts/gen-build-id.sh,
and C/header tests under tests/. Full Apache terms are in LICENSE-APACHE and the
core directories' LICENSE files. Required C headers stay with the buildable core.

SDK/API/client code (api/, implementations/, including Go), autopilot, broker,
camera, deployment, integrations, report, TACACS, remaining scripts/tools and
non-C integration tests now carry the proprietary policy. Commercial terms are
not supplied. The root LICENSE records this status without inventing an agreement.

These files were previously covered by Apache grants. Those grants remain valid
for the versions and material covered, including unchanged material here. New
policy headers do not establish exclusive proprietary rights or revoke existing
permissions. LICENSING-CONFLICTS.json records the previous source revision,
transitioned paths, and embedded Apache references preserved verbatim. Existing
copyright notices name Third Level IT LLC; ownership/authority for any new grant
must be established by the rights holder, not inferred from this policy file.

cJSON retains its embedded MIT license and attribution; src/third_party/README
is unchanged. pkcs11_min.h has unresolved provenance/terms and is not assigned a
new license. Historical deployment files, fixture/vector payloads, signed evidence
and copied documentation retain their original bytes, provenance and notices.
