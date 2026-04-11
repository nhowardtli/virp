VIRP Phase 1 Formal Proofs 
Machine-checked proofs of the VIRP observation ingest path under an unbounded Dolev-Yao adversary, in two independent tools. 
Cited by draft-howard-virp-05 §16.1 (Formal Verification). 
What is proven 
Two properties, verified in both ProVerif and Tamarin: 
Signing-key secrecy. The HMAC key k never leaks to the adversary, regardless of how many sessions run in parallel or what messages the
adversary injects, drops, or replays.
Non-injective agreement. Every Accepted(n, m) event on the receiver corresponds to a genuine Sent(n, m) event by the legitimate signer.
No forgery. No tampering. No substitution of observation content. The adversary cannot cause the receiver to accept any (counter,
observation) pair the signer did not originate. 
Together these establish Security Goal G1 (Observation Non-Forgeability) from the draft, modulo the standard EUF-CMA assumption on HMAC. 
What is not yet proven 
Injective agreement — the stronger claim that every accepted observation corresponds to a distinct send, and therefore that replays are rejected — is
not closed automatically in either tool. 
This is not a protocol flaw. Tamarin’s automatic backward search unrolls the monotonic counter one increment at a time rather than reasoning inductively
about it, and closing the proof requires hand-written helper invariants (signer-state monotonicity, verifier-state monotonicity, uniqueness of Sent events
per counter value). This is the same obstruction encountered in the Tamarin Yubikey proof (Künnemann & Steel, STM 2012), and the fix is mechanical
rather than conceptual. Tracked as a TODO for a subsequent draft revision. 
Replay resistance in the current draft is enforced at the specification level by the per-sender monotonic-counter ingest rule in §12.4 of draft-howard
virp-05. 
FilesFile Tool Purposevirp_p1_step10.pv ProVerif Counter model, three fixed-counter signersvirp_p1_step11.pv ProVerif Fresh-counter-per-session variantvirp_p1.spthy Tamarin Multiset-rewriting model, sound mutable statevirp_p1.out — Tamarin run output with verification summary 
Reproducing 
ProVerif 
Install (opam is the most reliable path): 
sudo apt install opam graphviz
opam init -y && eval $(opam env)
opam install -y proverif

Run: 
proverif virp_p1_step11.pv | grep -E "RESULT"

Expected output: 
RESULT not attacker(k[]) is true.
RESULT inj-event(Accepted(n_1,m_1)) ==> inj-event(Sent(n_1,m_1)) cannot be proved.
RESULT (but event(Accepted(n_1,m_1)) ==> event(Sent(n_1,m_1)) is true.)
RESULT event(Accepted(n_1,m1)) && event(Accepted(n_1,m2)) ==> m1 = m2 cannot be proved.

The two true results are what this directory claims. The two cannot be proved results correspond to the injective agreement gap described above;
ProVerif’s Horn-clause abstraction over the receiver state cell is the proximate reason these do not close in ProVerif specifically. 
Tamarin 
Install the prebuilt binary from GitHub releases plus Maude from apt: 
cd /tmp
wget https://github.com/tamarin-prover/tamarin-prover/releases/download/1.10.0/tamarin-prover-1.10.0-linux64-ubuntu.tar.gz
tar xzf tamarin-prover-1.10.0-linux64-ubuntu.tar.gz
sudo mv tamarin-prover /usr/local/bin/
sudo apt install -y maude graphvizRun (set UTF-8 locale so Tamarin can print ∀ to stdout): 
export LC_ALL=C.UTF-8
tamarin-prover --prove virp_p1.spthy 2>&1 | tee virp_p1.out
tail -12 virp_p1.out

Expected summary: 
summary of summaries:
analyzed: virp_p1.spthy
  key_secrecy (all-traces): verified (2 steps)
noninjective_agreement (all-traces): verified (5 steps)
counter_unique (all-traces): [inconclusive — helper lemmas needed]
injective_agreement (all-traces): [inconclusive — helper lemmas needed]

The first two are the claimed results. The second two are the documented gap; do not kill the run early expecting them to close. 
Tool versions used 
ProVerif (current stable via opam at time of proof)
Tamarin 1.10.0 (git cb62c30, built 2024-10-30)
Maude 3.1 
Reproducing with other versions is expected to work but has not been tested. 
Status 
virp_p1.spthy and virp_p1_step11.pv are the canonical models.
virp_p1_step10.pv is retained as the intermediate ProVerif model with three fixed-counter signers; it verifies the same two properties and is
kept for reference.
Helper-lemma work for full injective agreement is tracked as future work against this directory.
