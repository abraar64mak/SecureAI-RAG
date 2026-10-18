"""Isolated latency benchmark of the non-LLM stages (run with nothing else on the machine).

    python -m eval.latency_bench --out results/latency_bench.csv
Reports the per-query median over repeated passes of the 200 benign queries, per stage, plus ingestion ms/doc.
"""
from __future__ import annotations

import argparse

import pandas as pd

from defenses.config import preset
from eval.harness import LAT_KEYS, run_benign
from target.llm import get_llm
from target.rag import World

STAGES = ["none", "ingestion", "retrieval", "prompt", "output", "all"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results/latency_bench.csv")
    ap.add_argument("--repeats", type=int, default=7)
    a = ap.parse_args()
    w = World()
    llm = get_llm("sim:llama-like")
    rows = []
    for name in STAGES:
        cfg = preset(name)
        run_benign(w, cfg, llm)  # warm-up
        meds = pd.concat([run_benign(w, cfg, llm).assign(rep=i) for i in range(a.repeats)])
        per = {k: meds[f"ms_{k}"].median() for k in LAT_KEYS}
        layers = sum(v for k, v in per.items() if k != "generate")
        _, st = w.base_index(cfg)
        rows.append(dict(config=name, **{f"ms_{k}": round(v, 3) for k, v in per.items()}, layers_total_ms=round(layers, 3),
                         ingest_ms_per_doc=round(st["ms"] / st["docs"], 3)))
    df = pd.DataFrame(rows)
    df["added_ms"] = (df.layers_total_ms - df.loc[df.config == "none", "layers_total_ms"].iloc[0]).round(3)
    df.to_csv(a.out, index=False)
    print(df.to_string(index=False))


if __name__ == "__main__":
    main()
