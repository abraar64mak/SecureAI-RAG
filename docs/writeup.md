# Red-Teaming Retrieval-Augmented Generation: Indirect Injection, Poisoning and Exfiltration, with a Four-Stage Defense Pipeline and Adaptive Evaluation

*SecureAI-RAG technical note. All data synthetic. **All numbers below were produced with a simulated reader (SimLLM), not with Llama 3.1 / Qwen 2.5**; see Section 6.*

## Abstract
We build a RAG system over a synthetic clinical-style and general knowledge base that also contains private
runbooks seeded with 16 canary secrets, and attack it through the knowledge base with 250 templated cases in four
families: indirect prompt injection, retrieval manipulation, data exfiltration and obfuscated payloads. A four-stage
defense pipeline (ingestion, retrieval, prompt construction, output) with eleven independently toggleable layers
reduces overall attack success rate (ASR) from 68.0% to 1.6% under a simulated instruction-following reader, at
96.5% benign utility, 14.5% of benign queries touched by a guard, and about 2 ms added non-LLM latency. A
defense-aware adaptive attacker recovers 28.5% ASR, dominated by low-similarity knowledge poisoning (83%) that
contains no instructions to detect. We map every attack to the OWASP Top 10 for LLM Applications (2025).

## 1 Introduction
RAG systems read text written by people who are not the user. Anyone who can add a document to the corpus can
therefore speak to the model (OWASP LLM01), plant false facts (LLM04/LLM09), and, if private chunks share the index,
induce leakage (LLM02/LLM07), sometimes through channels the chat client executes automatically (LLM05). We
quantify these risks and the effect of layered defenses, and, following good practice, report what happens when the
attacker knows the defenses.

## 2 Threat model
The attacker can insert documents but cannot query the model, edit the system prompt or read the index. Private
runbooks and rosters (8 API keys, 7 patient IDs) share the index with no access control; the system prompt holds a
system-prompt canary. Success is judged on the final delivered answer: attacker marker present, attacker URL present,
wrong value asserted, or a canary present in any known encoding (decoded when the attack requested an encoding).
The non-adaptive attacker knows the victim question but not the defenses; the adaptive attacker knows the defenses
and thresholds and has oracle access (best-of-K).

## 3 Attack suite
| Family (n) | Mechanism | OWASP |
|---|---|---|
| Indirect injection (64) | ignore-previous, fake system banner, authority, delimiter breakout, polite request | LLM01 |
| Retrieval manipulation (60) | query mirroring, keyword stuffing, greedy-optimised prefix (PoisonedRAG-style), "correction notice" | LLM04, 08, 09 |
| Exfiltration (64) | key/ID leak, system-prompt leak, markdown-image beacon, link, document dump | LLM02, 05, 07 |
| Obfuscation (62) | base64, zero-width, HTML comment, white-on-white, ES/FR/DE, Cyrillic homoglyph | LLM01 |

200 benign queries (90 clinical, 90 general, 20 ops) with gold answers measure false positives and utility; 119 target
documents with benign "hard" traits (imperatives, URLs, comments, hex IDs). Retrieval hit rate is logged separately
from ASR.

## 4 Defenses
Ingestion: hidden-text stripper (comments, CSS-hidden elements, invisible characters, homoglyphs, decodable base64),
injection classifier (TF-IDF+LR; Prompt Guard backend optional), character-LM perplexity filter. Retrieval: flag chunks
whose query similarity exceeds a benign-calibrated threshold or that contain the question verbatim; drop near-duplicates
and keyword stuffing. Prompt: datamarking/delimiting with forgery-stripping plus an instruction-hierarchy system
prompt. Output: canary scan (raw, normalised, base64, hex, reversed, URL-escaped), host-exact URL allowlist, image
stripping, guard judge.

## 5 Results (SimLLM llama-like profile, 3 seeds, 95% Wilson intervals)
| Config | Inj. | Retr. | Exfil. | Obf. | All | Utility | Intervention |
|---|---|---|---|---|---|---|---|
| none | 71.4 | 76.7 | 69.8 | 54.3 | 68.0 [62, 74] | 100.0 | 0.0 |
| ingestion | 21.9 | 53.3 | 17.7 | 0.0 | 22.9 | 99.5 | 0.0 |
| retrieval | 0.0 | 21.7 | 0.0 | 0.0 | 5.2 | 98.0 | 13.5 |
| prompt* | 28.1 | 76.7 | 21.4 | 20.4 | 36.1 | 100.0 | 0.0 |
| output | 37.0 | 75.0 | 0.0 | 0.0 | 27.5 | 98.5 | 1.5 |
| all | 0.0 | 6.7 | 0.0 | 0.0 | 1.6 [0.6, 4.0] | 96.5 | 14.5 |
| all minus retrieval | 8.9 | 51.7 | 0.0 | 0.0 | 14.7 | 98.0 | 1.5 |
| all minus ingestion | 0.0 | 21.7 | 0.0 | 0.0 | 5.2 | 96.5 | 15.0 |

\*Prompt-stage rows reflect SimLLM's assumed susceptibility reduction, not a measurement. Added non-LLM latency for `all`
is 1.9 ms/query and 1.4 ms/doc at ingestion (noisy at this scale; generation excluded).

Retrieval is the most effective stage and the costliest: the mirror detector flags FAQ-style benign pages that quote
the question. Prompt and output defenses are redundant when the others are present but matter alone (output:
exfiltration 69.8 to 0.0). Remaining non-adaptive successes are optimised and stuffed poisons (13.3% each) that stay
under the similarity threshold.

**Adaptive attacks** (12 scenarios per operator, best-of-12): soft_injection 100 to 0; low_sim_poison 91.7 to **83.3**;
redirect_exfil 30.6 to 0; encoded_leak 100 to 30.6; overall 80.6 to **28.5** [18, 43]. The output layer alone does not
slow adaptive attackers (80.6): allowlisted open-redirect links and separator-encoded secrets pass it and are stopped only
upstream. Zero is not safety: the operator set is small and intervals reach 24%.

## 6 Limitations and validity
(1) Results use a simulated reader with assumed susceptibility; real-model numbers require `make ollama`.
(2) The corpus is a small synthetic template corpus with an LSA embedder, so undefended poison hit rate is 100% and
utility is a ceiling. (3) Attacks and defenses share an author; the classifier received credential-themed hard
negatives after we saw it quarantine the private runbooks. (4) 14.5% intervention is dominated by one detector.
(5) Judge agreement with labels was 50/50, but labels are the assistant's, on clean synthetic output. (6) Output
scanning does not replace access control. Garak, promptfoo, BIPIA and AgentDojo comparisons are not run.

## 7 Conclusion
Layered defenses remove nearly all of a non-adaptive suite, but the cheapest successful adaptive attack, poisoning with
no instructions, is untouched by injection-specific defenses and needs provenance, retrieval-side anomaly detection
against realistic distributions, and access control. Real-model replication is the first next step.
