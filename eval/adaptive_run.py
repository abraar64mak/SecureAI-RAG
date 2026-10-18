"""Evaluate the adaptive attack suite (best-of-K per scenario) under chosen configs.

    python -m eval.adaptive_run --llm sim:llama-like --seeds 3 --out results/sim-llama-like
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

import pandas as pd

from attacks.adaptive import generate
from attacks.base import AttackCase
from defenses.config import preset
from eval.harness import run_attacks
from eval.report import FAM_COLOR, _style, md_table, pct, wilson
from target.llm import get_llm
from target.rag import World

ADAPT_CONFIGS = ["none", "ingestion", "retrieval", "prompt", "output", "all"]
OPS_COLOR = {"soft_injection": "#0072B2", "low_sim_poison": "#E69F00", "redirect_exfil": "#009E73", "encoded_leak": "#D55E00"}


def best_of_k(df: pd.DataFrame, cases: list[AttackCase]) -> pd.DataFrame:
    grp = {c.case_id: c.meta["group"] for c in cases}
    df = df.assign(group=df.case_id.map(grp))
    per = df.groupby(["config", "seed", "subtype", "group"], as_index=False).agg(best=("rule_success", "max"), mean=("rule_success", "mean"))
    return per.groupby(["config", "subtype", "group"], as_index=False)[["best", "mean"]].mean()


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", default="sim:llama-like")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--out", default=None)
    ap.add_argument("--k", type=int, default=12)
    ap.add_argument("--embedder", default=None)
    a = ap.parse_args(argv)
    out = Path(a.out or f"results/{a.llm.replace(':', '-')}")
    out.mkdir(parents=True, exist_ok=True)
    world = World(embedder=a.embedder)
    cases = generate(world, random.Random(99), k=a.k)
    (out / "adaptive_cases.jsonl").write_text("\n".join(json.dumps(c.to_dict(), ensure_ascii=False) for c in cases))
    frames = []
    for seed in range(a.seeds):
        llm = get_llm(a.llm, seed)
        for name in ADAPT_CONFIGS:
            d = run_attacks(world, preset(name), llm, cases, seed=seed)
            frames.append(d)
            print(f"seed={seed} {name:<10} per-candidate ASR={d.rule_success.mean():.3f}", flush=True)
    df = pd.concat(frames)
    df.to_csv(out / "adaptive_attacks.csv", index=False)
    per = best_of_k(df, cases)
    rows = []
    for (cfg, op), g in per.groupby(["config", "subtype"]):
        lo, hi = wilson(g.best.mean(), len(g))
        rows.append(dict(config=cfg, operator=op, best_of_k=g.best.mean(), lo=lo, hi=hi, per_candidate=g["mean"].mean(), n_scenarios=len(g)))
    for cfg, g in per.groupby("config"):
        lo, hi = wilson(g.best.mean(), len(g))
        rows.append(dict(config=cfg, operator="ALL", best_of_k=g.best.mean(), lo=lo, hi=hi, per_candidate=g["mean"].mean(), n_scenarios=len(g)))
    tab = pd.DataFrame(rows)
    tab.to_csv(out / "adaptive_summary.csv", index=False)
    plot(tab, out / "adaptive_asr.png")
    wide = tab.assign(cell=tab.best_of_k.map(pct)).pivot(index="config", columns="operator", values="cell").reindex(ADAPT_CONFIGS).reset_index()
    (out / "adaptive_results.md").write_text(
        f"# Adaptive attacks - `{a.llm}`\n\nBest-of-{a.k} per scenario, {a.seeds} seed(s). ASR = share of scenarios where any candidate succeeded.\n\n"
        + md_table(wide) + "\n![adaptive](adaptive_asr.png)\n")
    print(wide.to_string())


def plot(tab: pd.DataFrame, path: Path):
    import matplotlib.pyplot as plt
    import numpy as np
    ops = ["soft_injection", "low_sim_poison", "redirect_exfil", "encoded_leak"]
    cfgs = [c for c in ADAPT_CONFIGS if c in set(tab.config)]
    fig, ax = plt.subplots(figsize=(10, 4.4))
    w = 0.2
    x = np.arange(len(cfgs))
    for i, op in enumerate(ops):
        s = tab[tab.operator == op].set_index("config").reindex(cfgs)
        ax.bar(x + (i - 1.5) * w, s.best_of_k * 100, w * 0.9, color=OPS_COLOR[op], label=op,
               yerr=[(s.best_of_k - s.lo) * 100, (s.hi - s.best_of_k) * 100], error_kw=dict(lw=0.8, capsize=2, ecolor="#555555"))
    ax.set_xticks(x, cfgs)
    ax.set_ylim(0, 105)
    ax.set_ylabel("adaptive ASR, best-of-K (%)")
    ax.set_title("Adaptive attacks vs defense configuration", loc="left", fontsize=11)
    ax.legend(ncol=4, frameon=False, loc="upper right", fontsize=8)
    _style(ax)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


if __name__ == "__main__":
    main()
