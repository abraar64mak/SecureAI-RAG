# Limitations

1. **Simulated LLM.** All committed results use `SimLLM`. Prompt-stage effectiveness and decoding ability are
   hand-set parameters, so those rows are assumptions. Re-run with `make ollama` for measured model behaviour.
2. **Synthetic, template-generated corpus and a small index (301 docs).** Retrieval is easy (undefended poison hit
   rate is 100%); the LSA embedder is not a neural embedder; the extractive QA reader is far simpler than an LLM, so
   utility is an optimistic ceiling. We added benign look-alike notes after the perplexity filter initially looked
   unrealistically strong (it was flagging "off-template", not "high-perplexity").
3. **Same author for attacks and defenses.** The classifier is trained on separate templates, but both reflect the
   same author's idea of an injection. Hard negatives (credential-themed benign text) were added after seeing the
   classifier quarantine the private runbooks, so its false-positive rate on this corpus is optimistic.
4. **Calibration.** Retrieval and perplexity thresholds are set at the 99th percentile on held-out/paraphrased
   queries; FPR is measured on 200 queries (wide intervals). The 14.5% intervention rate is dominated by the mirror
   detector on FAQ-style notes that quote questions.
5. **Adaptive attacker is modest**: four operators, best-of-12, 12 scenarios each. 0% adaptive success for two
   operators is not evidence of security. Low-similarity retrieval poisoning (83%) is unsolved here.
6. **No access control.** Output scanning mitigates but does not fix leakage of private chunks; ACL-aware retrieval
   and not indexing secrets are the actual remedies.
7. **Judge validation is weak.** Labels were produced by Claude, not a human, on clean SimLLM output (kappa 1.0).
8. **Latency.** Stage timings are millisecond-scale and noisy (some deltas are negative); generation time is
   excluded. With a real 7-8B model, generation (seconds) dominates.
9. **Not run:** Ollama, sentence-transformers, Meta Prompt Guard, Anthropic API, garak, promptfoo, BIPIA, AgentDojo.
10. **Scope:** text-only, single-turn, no tool use, no direct (user-side) injection, no multimodal content.
