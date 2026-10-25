# Repository consolidation — 2026-10-25

`main` is the active development branch. This consolidation integrates the recent
native signed execution, bounded VM/Windows provisioning, ASA/GNS3 integrations,
and FortiGate health cadence work. Home TLS/shutdown behavior is retained with
the newer execution implementation; the separate home shutdown regression is
included in the test battery.

Archived development tips remain under `archive/2026-10-25/` tags. These are
history preservation, **not releases, deployment instructions, or qualification
claims**. In particular the CMMC reconciliation/timed-standing candidates remain
experimental and are not integrated into runtime admission. Older demo,
licensing, deployment, and alternative consolidation lines remain available for
separate review rather than overriding newer code simply to combine histories.
No live infrastructure was changed during this repository cleanup.

To resume an archived line: `git switch -c work/name <archive-tag>`.
Historical laptop build products, private qualification captures, and old dirty
archive directories are retained locally, not added to the public source tree.
Separate repositories such as virp-rust, virp-witnessd and virp-audit are unchanged.

## Preserved development tips

| Archive tag | Original commit |
| --- | --- |
| `archive/2026-10-25/archive/demo-before-main-20260915` | `9b6595a43d3bc5675d5342cf988810afaa590612` |
| `archive/2026-10-25/demo/console-info` | `b7b7bb41a598dfeba85e71778888bfa38ed90efd` |
| `archive/2026-10-25/demo/plain-words` | `020859c3904f0787857c6b2f7da0ee50c28b0c31` |
| `archive/2026-10-25/deploy/313-netclaw-gate-handle` | `be5b47ab3f1dc88d2b0cb58aaa98f2e8be3de88f` |
| `archive/2026-10-25/deploy/313-unattributed-binary-2026-09-07` | `a25894e573191ca2422077f8d815fee38899e3cb` |
| `archive/2026-10-25/deploy/fed-error-2026-09-03` | `dc49b748389bd6712c3a02680f3692cca8266e7a` |
| `archive/2026-10-25/deploy/node2-42fe1fe` | `3370615fd68adc5fb5a9f23b3edd5dfaab90a98b` |
| `archive/2026-10-25/docs/agentdesktop-composition-2026-09-03` | `920f3e8b7d1e59e05b851fa836097066a2e91714` |
| `archive/2026-10-25/docs/attribution-design-brief` | `7ea9115ec7dd7cc4e0800e06632bdfedcbe7903b` |
| `archive/2026-10-25/docs/degraded-concurrency` | `eabb33c66806b9134a79f29172a85d19b10bb752` |
| `archive/2026-10-25/docs/deploy-discipline-2026-09-07` | `b9830cafb6d7bbebbec74a65598e5284d6e5ddd1` |
| `archive/2026-10-25/docs/hostkey-pinning-followup` | `e269da7c109b957a9aed7a3eecabc554f828397b` |
| `archive/2026-10-25/docs/meraki-phase0` | `6d4ebd5c97bfd6b0bf03601f8bad19e2fa888b12` |
| `archive/2026-10-25/docs/readme-v0.2.0` | `f9914a4e5ff5945b10d5be45ba5263d794876c1c` |
| `archive/2026-10-25/docs/retention-s5-amend` | `648efee5d83ae9db009793a3721a33551d245d31` |
| `archive/2026-10-25/docs/tacacs-milestone-2026-09-07` | `3ca463b54fb2b794613bf844ea338d32b94054c5` |
| `archive/2026-10-25/feat/asa-5525-governed` | `e3f6191440bb54cbd31dbb27fb8f5d861b3075a1` |
| `archive/2026-10-25/feat/black-passthrough` | `58bbf4711e02d8935899110694e397bd54672e83` |
| `archive/2026-10-25/feat/cmmc-gates-20261022` | `ab984cac6cc4a484d1d952df404c55c19fc246e6` |
| `archive/2026-10-25/feat/component-licensing` | `22c48e60a71a53abc32236388771e023d5672d60` |
| `archive/2026-10-25/feat/demo-lab` | `0ac76152d0efeb4b088975c94341c5cd349d0c9a` |
| `archive/2026-10-25/feat/demo-signup` | `2d259e1028bf657a1c4c5ef7135f29ebcfbfeccb` |
| `archive/2026-10-25/feat/device-enabled-flag` | `fe330bad5d85c3b520885e5e2429a2ff92047988` |
| `archive/2026-10-25/feat/fleet-add-sw-3850-prerebase` | `15edbf480ebd46003f78ee533cf652d0f1777493` |
| `archive/2026-10-25/feat/ios-classifier` | `3d46a0c550e77e8708fac9f184957e6b3f9db706` |
| `archive/2026-10-25/feat/node2-epoch-qualification` | `56982cd95040820ea7edd35dd016b4d183fa7421` |
| `archive/2026-10-25/feat/seat-session-namespace` | `e942fd612e17ee37965c775fe99f727f42bee7a3` |
| `archive/2026-10-25/feat/tacacs-server-hardening` | `eabbca5b4b6a06405b1617c251f74dbefe023a14` |
| `archive/2026-10-25/feat/verifier-baseline-tool` | `21a1be956efda6ae2a2207f2556c563f19860d70` |
| `archive/2026-10-25/fix/313-unit-manifest` | `ff56cc649ed72b9ebe4ea0d515bb2ef0e2552020` |
| `archive/2026-10-25/fix/E-reconciler-filter-canon` | `bf85b06831d2084e608ae54f233b6874400bb2db` |
| `archive/2026-10-25/fix/chain-verify-hash-index` | `ade5249041dcc93688ff285184bae9377ddfdae4` |
| `archive/2026-10-25/fix/export-head-entry-race` | `d1d33f4bcc616c579dd871b9aec70b206245b933` |
| `archive/2026-10-25/fix/fortigate-health-cadence-home-20261022` | `e5a1fe421f422ed80ce4c872acfb28f588eee456` |
| `archive/2026-10-25/fix/fortigate-hostkey-rsa-pref` | `ffaa4529d91d3a75a402a2755fc02014f86fb9e9` |
| `archive/2026-10-25/fix/home-wazuh-tls-20261003` | `f69d5fdbb8054b9b5903da27176a40197ed2441c` |
| `archive/2026-10-25/fix/session-owner-uid` | `ff0f809cf6599d03c99679b933ccb2443ef070ef` |
| `archive/2026-10-25/fix/signing-activation` | `aba582c228e4a4180de5036e744dd78b2f73779e` |
| `archive/2026-10-25/kestrel/secure-rw-20261015` | `77255fe3161ab407b4a3b98000368479e70b5d7d` |
| `archive/2026-10-25/lab/gns3-colo-readdress` | `06848ba59cf36df2295c06730c73da2076d3ef83` |
| `archive/2026-10-25/main` | `1f3386375b706a952129bad67f10fe834214fc05` |
| `archive/2026-10-25/main-900ec1d1` | `900ec1d1ab8c6e95bf4e3291c9ed499649129310` |
| `archive/2026-10-25/main-e1f2d2c2` | `e1f2d2c2af7fef7531f666378cf7c28a244f9efb` |
| `archive/2026-10-25/overnight/report-1` | `519ccd8118ddd810b41aab008fdbf94827096c70` |
| `archive/2026-10-25/overnight/report-2` | `9835b8d8212267e1bcf5b5435cc7a928285d4353` |
| `archive/2026-10-25/perf/replay-guard-index` | `54372d9cdcdcfcfc2820539f262fa27e87e887ab` |
| `archive/2026-10-25/perf/verify-closer-map-v2` | `8dfe6436ad306bab82383cc23d3d3859fa4023cc` |
| `archive/2026-10-25/rescue/feat/disposition-enum-2026-08-31` | `a07edfedb5e56415e1c166fdaf55c01b6249b147` |
| `archive/2026-10-25/rescue/feat/v3-observation-wiring-2026-08-31` | `9a44a00f55ad707763aa89c2f0f4887a4cce26ba` |
| `archive/2026-10-25/rescue/netclaw-cc841caa` | `cc841caa38ca539f37fa7b6edf5eefef56878bc3` |
| `archive/2026-10-25/stage/consolidate-2026-09-08` | `723f11e5092df522be085804fb8ab036f814e6fd` |
