# Results - `sim:strong`

Embedder `lsa`, 250 attack cases, 200 benign queries, 3 LLM seed(s).
ASR denominators are attack cases (seed-averaged); intervals are 95% Wilson.

## Attack success rate (rule-based)
| config | injection | retrieval | exfiltration | obfuscation | ALL | ALL 95% CI |
|---|---|---|---|---|---|---|
| none | 28.6% | 76.7% | 22.9% | 21.0% | 36.8% | [31, 43] |
| ingestion | 9.9% | 51.7% | 6.2% | 0.0% | 16.5% | [12, 22] |
| retrieval | 0.0% | 21.7% | 0.0% | 0.0% | 5.2% | [3, 9] |
| prompt | 4.2% | 76.7% | 4.2% | 3.8% | 21.5% | [17, 27] |
| output | 18.8% | 75.0% | 0.0% | 0.0% | 22.8% | [18, 28] |
| all | 0.0% | 6.7% | 0.0% | 0.0% | 1.6% | [1, 4] |
| all-minus-ingestion | 0.0% | 21.7% | 0.0% | 0.0% | 5.2% | [3, 9] |
| all-minus-retrieval | 0.0% | 50.0% | 0.0% | 0.0% | 12.0% | [9, 17] |
| all-minus-prompt | 0.0% | 6.7% | 0.0% | 0.0% | 1.6% | [1, 4] |
| all-minus-output | 0.0% | 6.7% | 0.0% | 0.0% | 1.6% | [1, 4] |

![ASR](asr_by_family.png)

## Utility and false positives on benign queries
`utility` = gold answer present; `utility_hard` = on queries whose source doc has imperatives/URLs/comments;
`fpr_query` = share of benign queries where a retrieval guard dropped a chunk or the output guard changed/blocked the answer;
`quarantine_rate` = clean chunks rejected at ingestion; `canary_leak` = canary in a benign answer.
| config | utility | utility_hard | fpr_query | quarantine_rate | canary_leak |
|---|---|---|---|---|---|
| all | 96.5% | 97.5% | 14.5% | 0.3% | 0.0% |
| all-minus-ingestion | 96.5% | 97.5% | 15.0% | 0.0% | 0.0% |
| all-minus-output | 98.0% | 100.0% | 13.0% | 0.3% | 0.0% |
| all-minus-prompt | 96.5% | 97.5% | 14.5% | 0.3% | 0.0% |
| all-minus-retrieval | 98.0% | 97.5% | 1.5% | 0.3% | 0.0% |
| ingestion | 99.5% | 100.0% | 0.0% | 0.3% | 0.0% |
| none | 100.0% | 100.0% | 0.0% | 0.0% | 0.0% |
| output | 98.5% | 97.5% | 1.5% | 0.0% | 0.0% |
| prompt | 100.0% | 100.0% | 0.0% | 0.0% | 0.0% |
| retrieval | 98.0% | 100.0% | 13.5% | 0.0% | 0.0% |

![tradeoff](tradeoff.png)

## Retrieval hit rate vs attack success (none vs all)
| config | family | retrieval_hit | in_context | asr | asr_given_in_context |
|---|---|---|---|---|---|
| all | exfiltration | 29.7% | 0.0% | 0.0% | - |
| all | injection | 26.6% | 0.0% | 0.0% | - |
| all | obfuscation | 33.9% | 0.0% | 0.0% | - |
| all | retrieval | 66.7% | 20.0% | 6.7% | 33.3% |
| none | exfiltration | 100.0% | 100.0% | 22.9% | 22.9% |
| none | injection | 100.0% | 100.0% | 28.6% | 28.6% |
| none | obfuscation | 100.0% | 100.0% | 21.0% | 21.0% |
| none | retrieval | 100.0% | 100.0% | 76.7% | 76.7% |

## Added latency (ms/query excluding generation) and ingestion cost
| config | added_ms | ingest_ms_per_doc | ms_generate |
|---|---|---|---|
| all | 2.51 | 2.96 | 2.25 |
| all-minus-ingestion | 1.52 | 1.76 | 2.30 |
| all-minus-output | 0.96 | 2.96 | 2.63 |
| all-minus-prompt | 1.07 | 2.96 | 2.35 |
| all-minus-retrieval | 1.19 | 2.96 | 2.24 |
| ingestion | 0.07 | 2.96 | 2.32 |
| none | 0.00 | 1.76 | 2.26 |
| output | -0.67 | 1.76 | 2.32 |
| prompt | 0.75 | 1.76 | 2.28 |
| retrieval | 0.70 | 1.76 | 2.53 |

![latency](latency.png)

## Ablation heatmap
![heatmap](ablation_heatmap.png)

Rule vs fuzzy-judge disagreement on attack outcomes: 0.0% of runs.
