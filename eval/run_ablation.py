"""Run every attack and every benign query under every defense configuration.

    python -m eval.run_ablation --llm sim:llama-like --seeds 3 --out results/sim-llama-like
    python -m eval.run_ablation --llm ollama:llama3.1:8b --seeds 1 --out results/ollama-llama3.1-8b
    python -m eval.run_ablation --llm ollama:qwen2.5:7b  --seeds 1 --out results/ollama-qwen2.5-7b
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import pandas as pd

from attacks.suite import SUITE_PATH, build_suite, load_suite, save_suite
from defenses.config import ALL_CONFIGS, SUBLAYER_CONFIGS, preset
from eval.harness import run_attacks, run_benign
from target.llm import get_llm
from target.rag import World


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", default="sim:llama-like")
    ap.add_argument("--seeds", type=int, default=3, help="repeat with different LLM seeds (use 1 for temperature-0 real models)")
    ap.add_argument("--out", default=None)
    ap.add_argument("--configs", default="main", help="main | all | comma list of preset names")
    ap.add_argument("--judge", default="fuzzy", help="fuzzy | llm (uses the same --llm as grader)")
    ap.add_argument("--limit", type=int, default=0, help="only the first N attack cases per family (smoke test)")
    ap.add_argument("--benign-limit", type=int, default=0, help="only the first N benign queries (smoke test / slow real models)")
    ap.add_argument("--embedder", default=None)
    ap.add_argument("--use-saved-suite", action="store_true", help="reuse data/attack_suite.jsonl (otherwise rebuilt: optimised attacks depend on the embedder)")
    args = ap.parse_args(argv)

    out = Path(args.out or f"results/{args.llm.replace(':', '-')}")
    out.mkdir(parents=True, exist_ok=True)
    world = World(embedder=args.embedder)
    if args.use_saved_suite and SUITE_PATH.exists():
        cases = load_suite()
    else:
        cases = build_suite(world)
        save_suite(cases)
    if args.limit:
        keep, seen = [], {}
        for c in cases:
            seen[c.family] = seen.get(c.family, 0) + 1
            if seen[c.family] <= args.limit:
                keep.append(c)
        cases = keep
    if args.benign_limit:
        world.benign = world.benign[: args.benign_limit]
    names = {"main": ALL_CONFIGS, "all": ALL_CONFIGS + SUBLAYER_CONFIGS}.get(args.configs) or args.configs.split(",")

    att, ben, ing = [], [], []
    t0 = time.time()
    for seed in range(args.seeds):
        llm = get_llm(args.llm, seed)
        judge = None
        if args.judge == "llm":
            from eval.judge import LLMJudge
            judge = LLMJudge(llm)
        for name in names:
            cfg = preset(name)
            a = run_attacks(world, cfg, llm, cases, judge=judge, seed=seed)
            b = run_benign(world, cfg, llm, seed=seed)
            att.append(a); ben.append(b)
            print(f"[{time.time() - t0:6.1f}s] seed={seed} {name:<24} ASR={a.rule_success.mean():.3f} utility={b.correct.mean():.3f}", flush=True)
    for name in names:
        _, st = world.base_index(preset(name))
        ing.append(dict(config=name, **st))
    pd.concat(att).to_csv(out / "attacks.csv", index=False)
    pd.concat(ben).to_csv(out / "benign.csv", index=False)
    pd.DataFrame(ing).to_csv(out / "ingestion.csv", index=False)
    json.dump(dict(llm=args.llm, seeds=args.seeds, configs=names, n_attacks=len(cases), n_benign=len(world.benign),
                   embedder=world.embedder.name, sim_threshold=world.sim_threshold, ppl_threshold=world.ppl.threshold),
              open(out / "run.json", "w"), indent=1)
    from eval.report import make_report
    make_report(out)


if __name__ == "__main__":
    main()
