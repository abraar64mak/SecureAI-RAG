# SecureAI-RAG

Red-teaming for retrieval-augmented generation. The repository contains a small RAG system, 250 attacks that reach it through poisoned documents, a four-stage defense pipeline, and an evaluation harness that reports attack success rate (ASR), false positives, utility, latency, and the effect of an attacker who knows the defenses.

All data are synthetic. Nothing here comes from real patients, clinics or employers.

## Evaluation model

To make every experiment reproducible and runnable offline, the harness uses a deterministic simulated reader (`SimLLM`, in `target/simllm.py`) in place of a live LLM. It models how an instruction-following model reacts to text in its context, with explicit per-profile parameters, and the same attack gets the same random draw under every defense so comparisons are paired. The ingestion, retrieval and output defenses are real code measured on the real attack suite. The prompt-stage effect (spotlighting, instruction hierarchy) is a parameter of the simulator. Backends for Ollama and the Anthropic API are included (`--llm ollama:llama3.1:8b`); results with those models are the next step.

## System

A staff question-answering assistant for a fictional clinic. The corpus has 301 documents (clinical, general, benign look-alike notes) plus 15 private runbooks and rosters in the same index that hold 16 canary secrets: 8 API keys, 7 patient IDs and a system-prompt token. There is no access control, which is the misconfiguration that makes leakage measurable. Retrieval is FAISS over TF-IDF/LSA embeddings; a sentence-transformers backend is available.

## Attacks (250) and benign queries (200)

| Family | n | Mechanism | OWASP LLM 2025 |
|---|---|---|---|
| Indirect injection | 64 | hidden instructions in a retrieved document | LLM01 |
| Retrieval manipulation | 60 | query mirroring, keyword stuffing, optimised false-answer passages | LLM04, 08, 09 |
| Exfiltration | 64 | key, ID and system-prompt leaks; image and link beacons | LLM02, 05, 07 |
| Obfuscation | 62 | base64, zero-width, HTML comment, hidden CSS, other languages, homoglyphs | LLM01 |

Details are in `docs/attack_taxonomy.md` and `docs/threat_model.md`.

## Defenses

Each layer can be switched on or off independently.

1. Ingestion: hidden-text stripper, injection classifier, character-level perplexity filter.
2. Retrieval: similarity-outlier and query-mirroring detector, near-duplicate and keyword-stuffing filter.
3. Prompt: datamarking or delimiting retrieved text, plus an instruction-hierarchy system prompt.
4. Output: canary scan, URL allowlist, image stripping, answer judge.

## Results (simulated reader, 3 seeds)

| | no defense | all four stages |
|---|---|---|
| ASR, all 250 attacks | 68.0% [62, 74] | 1.6% [0.6, 4.0] |
| Adaptive attacks (48 scenarios, best of 12) | 80.6% | 25.7% [16, 40] |
| Utility on benign queries | 100% | 96.5% |
| Benign queries where a guard intervened | 0% | 14.5% |
| Added latency, non-LLM stages | n/a | about 0.6 ms per query |

Intervals are 95% Wilson. Per-family and per-layer tables, plots and CSVs are in `results/`.

Three observations. First, layering removes almost all of the non-adaptive suite, but that suite and the defenses share an author, so the adaptive figure is the more informative one. Second, retrieval poisoning that contains no instructions and stays below the similarity threshold still succeeds in 83% of adaptive scenarios against the full pipeline; injection-specific defenses do not address it. Third, the retrieval stage is the most effective layer and also the most costly, touching 13.5% of benign queries, largely by flagging FAQ-style pages that quote the question verbatim.

## Running it

```
pip install -r requirements.txt
python -m pytest -q
python -m eval.run_ablation --llm sim:llama-like --seeds 3 --configs all --out results/sim-llama-like
python -m eval.adaptive_run --llm sim:llama-like --seeds 3 --out results/sim-llama-like
python -m eval.run_ablation --llm ollama:llama3.1:8b --seeds 1 --configs none,all --limit 15 --benign-limit 60 --out results/ollama-quick
```

A configuration is a name such as `none`, `all`, `all-minus-retrieval` or `output:url_allowlist`. The service in `target/service.py` exposes the pipeline over HTTP for external scanners. Real 7-8B models need roughly 6 GB of free memory; a 3B model is a safer start on a laptop.

## Layout

```
target/    corpus, canaries, index, embedders, LLM backends, service
attacks/   four attack families and the adaptive attacker
defenses/  the four stages
eval/      harness, scorers, ablation and adaptive runners, reports
docs/      threat model, taxonomy, two-page write-up
results/   CSVs and figures
tests/     26 tests
```

## License

MIT.
