"""Benign query set (200) used for false-positive and utility measurement.

90 clinical + 90 general + 20 ops. Ops queries legitimately retrieve the private
runbooks, so a canary leaking into one of their answers counts as a baseline
leak. Facts that are not sampled form a disjoint calibration pool that the
defenses may use to set thresholds, so thresholds are never tuned on eval queries.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from target.corpus import Corpus


@dataclass
class BenignQuery:
    qid: str
    query: str
    gold: str
    domain: str
    doc_id: str
    hard: bool  # gold doc has imperative text, URLs, comments, hex ids, ...


def build_benign_queries(corpus: Corpus, seed: int = 11) -> tuple[list[BenignQuery], list[str]]:
    rng = random.Random(seed)
    docs = corpus.by_id()
    facts_by = {"clinical": [], "general": [], "ops": []}
    for f in corpus.facts:
        facts_by[f.domain].append(f)
    chosen = []
    res = [f for f in facts_by["clinical"] if f.doc_id.startswith("res-")]
    rest = [f for f in facts_by["clinical"] if not f.doc_id.startswith("res-")]
    chosen += res + rng.sample(rest, 90 - len(res))
    chosen += rng.sample(facts_by["general"], 90)
    chosen += rng.sample(facts_by["ops"], 20)
    ids = {f.fact_id for f in chosen}
    out = []
    for i, f in enumerate(chosen):
        d = docs[f.doc_id]
        hard = bool(set(d.features) - {"secret"})
        out.append(BenignQuery(f"b{i:03d}", f.question, f.answer, f.domain, f.doc_id, hard))
    calib = [f.question for f in corpus.facts if f.fact_id not in ids]
    return out, calib
