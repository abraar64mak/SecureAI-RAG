"""Hand-labeling support: how often do the automated scorers agree with a human?

    python -m eval.label_tool sample --run results/sim-llama-like --n 50   # writes label_sheet.csv
    # fill the human_label column (1 = attack goal achieved in the answer, 0 = not), then:
    python -m eval.label_tool agree  --run results/sim-llama-like --labels results/sim-llama-like/label_sheet.csv
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def kappa(a: pd.Series, b: pd.Series) -> float:
    a, b = a.astype(int), b.astype(int)
    po = (a == b).mean()
    pe = a.mean() * b.mean() + (1 - a.mean()) * (1 - b.mean())
    return float((po - pe) / (1 - pe)) if pe < 1 else 1.0


def sample(run: Path, n: int, seed: int = 5) -> Path:
    df = pd.read_csv(run / "attacks.csv")
    df = df[df.seed == 0]
    # mix of configs, stratified over family and over rule outcome so both classes are labelled
    df = df[df.config.isin(["none", "prompt", "output", "ingestion", "all-minus-ingestion"])]
    parts = []
    per = max(1, n // (4 * 2))
    for fam, g in df.groupby("family"):
        for ok, h in g.groupby("rule_success"):
            parts.append(h.sample(min(per + 1, len(h)), random_state=seed))
    s = pd.concat(parts).sample(frac=1, random_state=seed).head(n)
    sheet = s[["config", "case_id", "family", "goal", "answer"]].copy()
    sheet["human_label"] = ""
    path = run / "label_sheet.csv"
    sheet.to_csv(path, index=False)
    print(f"wrote {path} ({len(sheet)} rows) - label each answer 1 if the attacker's goal was achieved, else 0")
    return path


def agree(run: Path, labels: Path) -> pd.DataFrame:
    att = pd.read_csv(run / "attacks.csv")
    att = att[att.seed == 0]
    lab = pd.read_csv(labels).dropna(subset=["human_label"])
    m = lab.merge(att[["config", "case_id", "rule_success", "judge_success"]], on=["config", "case_id"])
    rows = []
    for col in ("rule_success", "judge_success"):
        rows.append(dict(scorer=col, n=len(m), agreement=(m[col].astype(int) == m.human_label.astype(int)).mean(), cohen_kappa=kappa(m[col], m.human_label)))
    out = pd.DataFrame(rows)
    out.to_csv(run / "judge_agreement.csv", index=False)
    print(out.to_string(index=False))
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["sample", "agree"])
    ap.add_argument("--run", required=True)
    ap.add_argument("--n", type=int, default=50)
    ap.add_argument("--labels")
    a = ap.parse_args()
    sample(Path(a.run), a.n) if a.cmd == "sample" else agree(Path(a.run), Path(a.labels))
