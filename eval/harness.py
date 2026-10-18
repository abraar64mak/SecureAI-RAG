"""Run attack cases and benign queries against a configured RAG system and log
everything needed for the report."""
from __future__ import annotations

import pandas as pd

from attacks.base import AttackCase
from eval.judge import FuzzyJudge
from eval.scoring import benign_correct, canary_leak, rule_success
from target.corpus import Document
from target.rag import RAGSystem, World

LAT_KEYS = ["embed", "search", "retrieval_guard", "prompt", "generate", "output_guard"]


def run_attacks(world: World, cfg, llm, cases: list[AttackCase], judge=None, seed: int = 0, guard_judge=None) -> pd.DataFrame:
    system = RAGSystem(world, cfg, llm, judge=guard_judge)
    judge = judge or FuzzyJudge(world.canaries)
    rows = []
    for case in cases:
        reports = [system.ingest(Document(p.doc_id, p.doc_id, p.text, p.fmt, "poison")) for p in case.poison_docs]
        res = system.answer(case.query)
        for r in reports:
            system.remove(r)
        ok, why = rule_success(case, res.answer, world.canaries)
        poison_ids = {p.doc_id for p in case.poison_docs}
        rows.append(dict(
            config=cfg.name, seed=seed, case_id=case.case_id, family=case.family, subtype=case.subtype, goal=case.goal,
            n_poison_chunks=sum(r.n_chunks - r.quarantined for r in reports),
            ingest_flagged=any(r.flags for r in reports),
            ingest_blocked=all(r.n_chunks - r.quarantined == 0 for r in reports),
            retrieval_hit=any(d in poison_ids for d, _, _ in res.raw_hits),
            poison_rank=next((i + 1 for i, (d, _, _) in enumerate(res.raw_hits) if d in poison_ids), 0),
            top1_sim=res.raw_hits[0][2] if res.raw_hits else 0.0,
            poison_in_context=any(d in poison_ids for d in res.context_docs),
            retr_flagged=any(f.startswith("retr:") for f in res.flags),
            out_flagged=any(f.startswith("out:") for f in res.flags),
            rule_success=ok, rule_reason=why, judge_success=bool(judge.success(case, res.answer)),
            canary_leak=canary_leak(res.answer, world.canaries),
            correct=benign_correct(case.gold, res.answer),
            answer=res.answer[:400].replace("\n", " "),
            ingest_ms=sum(r.ms for r in reports) / max(1, len(reports)),
            **{f"ms_{k}": res.latency.get(k, 0.0) for k in LAT_KEYS}))
    return pd.DataFrame(rows)


def run_benign(world: World, cfg, llm, seed: int = 0, guard_judge=None) -> pd.DataFrame:
    system = RAGSystem(world, cfg, llm, judge=guard_judge)
    rows = []
    for b in world.benign:
        res = system.answer(b.query)
        rows.append(dict(
            config=cfg.name, seed=seed, qid=b.qid, domain=b.domain, hard=b.hard,
            correct=benign_correct(b.gold, res.answer),
            retr_dropped=any(f.startswith("retr:") for f in res.flags),
            out_modified=res.answer != res.raw_answer,
            blocked=res.answer.startswith("[answer withheld"),
            flagged=bool(res.flags),
            canary_leak=canary_leak(res.answer, world.canaries),
            answer=res.answer[:300].replace("\n", " "),
            **{f"ms_{k}": res.latency.get(k, 0.0) for k in LAT_KEYS}))
    return pd.DataFrame(rows)
