"""Turn attacks.csv / benign.csv / ingestion.csv into tables, plots and results.md."""
from __future__ import annotations

import json
import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

FAMILIES = ["injection", "retrieval", "exfiltration", "obfuscation"]
FAM_COLOR = {"injection": "#0072B2", "retrieval": "#E69F00", "exfiltration": "#009E73", "obfuscation": "#D55E00"}  # Okabe-Ito (CVD-safe)
MAIN = ["none", "ingestion", "retrieval", "prompt", "output", "all"]
LAT = ["embed", "search", "retrieval_guard", "prompt", "output_guard"]  # generation excluded: dominated by the LLM


def wilson(p: float, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def per_case(att: pd.DataFrame, col: str = "rule_success") -> pd.DataFrame:
    """Average over seeds first so the unit of analysis is the attack case."""
    return att.groupby(["config", "family", "subtype", "case_id"], as_index=False)[col].mean()


def asr_table(att: pd.DataFrame, col: str = "rule_success") -> pd.DataFrame:
    pc = per_case(att, col)
    rows = []
    for (cfg, fam), g in pc.groupby(["config", "family"]):
        p, n = g[col].mean(), len(g)
        lo, hi = wilson(p, n)
        rows.append(dict(config=cfg, family=fam, asr=p, lo=lo, hi=hi, n=n))
    for cfg, g in pc.groupby("config"):
        p, n = g[col].mean(), len(g)
        lo, hi = wilson(p, n)
        rows.append(dict(config=cfg, family="ALL", asr=p, lo=lo, hi=hi, n=n))
    return pd.DataFrame(rows)


def retrieval_table(att: pd.DataFrame) -> pd.DataFrame:
    g = att.groupby(["config", "family"]).agg(retrieval_hit=("retrieval_hit", "mean"), in_context=("poison_in_context", "mean"),
                                              ingest_blocked=("ingest_blocked", "mean"), asr=("rule_success", "mean")).reset_index()
    ctx = att[att.poison_in_context].groupby(["config", "family"]).rule_success.mean().rename("asr_given_in_context")
    return g.merge(ctx, on=["config", "family"], how="left")


def benign_table(ben: pd.DataFrame, ing: pd.DataFrame) -> pd.DataFrame:
    g = ben.groupby("config").agg(utility=("correct", "mean"), flagged=("flagged", "mean"), retr_dropped=("retr_dropped", "mean"),
                                  out_modified=("out_modified", "mean"), blocked=("blocked", "mean"), canary_leak=("canary_leak", "mean")).reset_index()
    g["fpr_query"] = ben.assign(i=ben.retr_dropped | ben.out_modified | ben.blocked).groupby("config").i.mean().values
    hard = ben[ben.hard].groupby("config").correct.mean().rename("utility_hard")
    g = g.merge(hard, on="config", how="left")
    ing = ing.assign(quarantine_rate=ing.quarantined / ing.chunks, docs_flagged_rate=ing.flagged_docs / ing.docs)
    return g.merge(ing[["config", "quarantine_rate", "docs_flagged_rate"]], on="config", how="left")


def latency_table(att: pd.DataFrame, ben: pd.DataFrame, ing: pd.DataFrame) -> pd.DataFrame:
    cols = [f"ms_{k}" for k in LAT]
    g = ben.groupby("config")[cols].mean()
    g["ms_layers_total"] = g.sum(axis=1)
    if "none" in g.index:
        g["added_ms"] = g.ms_layers_total - g.loc["none", "ms_layers_total"]
    g["ms_generate"] = ben.groupby("config").ms_generate.mean()
    ing = ing.set_index("config")
    g["ingest_ms_per_doc"] = (ing.ms / ing.docs).reindex(g.index)
    return g.reset_index()


# --------------------------------------------------------------------------- plots
def _style(ax):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.grid(axis="y", color="#dddddd", lw=0.6)
    ax.set_axisbelow(True)


def plot_asr(tab: pd.DataFrame, path: Path, configs=MAIN, title="Attack success rate by family and defense configuration"):
    configs = [c for c in configs if c in set(tab.config)]
    fig, ax = plt.subplots(figsize=(11, 4.6))
    w = 0.2
    x = np.arange(len(configs))
    for i, fam in enumerate(FAMILIES):
        sub = tab[tab.family == fam].set_index("config").reindex(configs)
        ax.bar(x + (i - 1.5) * w, sub.asr * 100, w * 0.9, color=FAM_COLOR[fam], label=fam,
               yerr=[(sub.asr - sub.lo) * 100, (sub.hi - sub.asr) * 100], error_kw=dict(lw=0.8, capsize=2, ecolor="#555555"))
    ax.set_xticks(x, configs)
    ax.set_ylabel("ASR (%)  [95% Wilson CI]")
    ax.set_ylim(0, 105)
    ax.set_title(title, loc="left", fontsize=11)
    ax.legend(ncol=4, frameon=False, loc="upper right")
    _style(ax)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_heatmap(tab: pd.DataFrame, path: Path, configs: list[str]):
    configs = [c for c in configs if c in set(tab.config)]
    fams = FAMILIES + ["ALL"]
    M = np.array([[tab[(tab.config == c) & (tab.family == f)].asr.mean() * 100 for f in fams] for c in configs])
    fig, ax = plt.subplots(figsize=(6.2, 0.45 * len(configs) + 1.4))
    im = ax.imshow(M, cmap="Blues", vmin=0, vmax=100, aspect="auto")
    ax.set_xticks(range(len(fams)), fams)
    ax.set_yticks(range(len(configs)), configs)
    for i in range(len(configs)):
        for j in range(len(fams)):
            ax.text(j, i, f"{M[i, j]:.0f}", ha="center", va="center", fontsize=8, color="white" if M[i, j] > 55 else "#222222")
    ax.set_title("ASR (%) ablation: config x family", loc="left", fontsize=10)
    fig.colorbar(im, ax=ax, shrink=0.8)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_tradeoff(asr_all: pd.DataFrame, ben: pd.DataFrame, path: Path):
    m = asr_all[asr_all.family == "ALL"].merge(ben[["config", "utility"]], on="config")
    fig, ax = plt.subplots(figsize=(6.4, 4.4))
    ax.scatter(m.asr * 100, m.utility * 100, s=36, color="#0072B2", zorder=3)
    for _, r in m.iterrows():
        ax.annotate(r.config, (r.asr * 100, r.utility * 100), textcoords="offset points", xytext=(5, 4), fontsize=7)
    ax.set_xlabel("Overall attack success rate (%)  - lower is better")
    ax.set_ylabel("Utility on benign queries (%)  - higher is better")
    ax.set_title("Security / utility trade-off", loc="left", fontsize=10)
    _style(ax)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_latency(lat: pd.DataFrame, path: Path):
    lat = lat[lat.config.isin(MAIN)].set_index("config").reindex([c for c in MAIN if c in set(lat.config)])
    cols = [f"ms_{k}" for k in LAT]
    colors = ["#999999", "#56B4E9", "#E69F00", "#009E73", "#D55E00"]
    fig, ax = plt.subplots(figsize=(7.5, 4))
    bottom = np.zeros(len(lat))
    for c, col in zip(cols, colors):
        ax.bar(lat.index, lat[c], bottom=bottom, color=col, width=0.6, label=c.removeprefix("ms_"))
        bottom += lat[c].values
    ax.set_ylabel("ms per query (excl. LLM generation)")
    ax.set_title("Pipeline latency by stage", loc="left", fontsize=10)
    ax.legend(frameon=False, ncol=3, fontsize=8)
    _style(ax)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


# --------------------------------------------------------------------------- markdown
def md_table(df: pd.DataFrame, fmt: dict | None = None) -> str:
    fmt = fmt or {}
    head = "| " + " | ".join(df.columns) + " |\n|" + "---|" * len(df.columns) + "\n"
    rows = []
    for _, r in df.iterrows():
        rows.append("| " + " | ".join(fmt.get(c, lambda v: v if isinstance(v, str) else f"{v:g}")(r[c]) if pd.notna(r[c]) else "-" for c in df.columns) + " |")
    return head + "\n".join(rows) + "\n"


def pct(v):
    return f"{v * 100:.1f}%"


def make_report(out: Path) -> None:
    out = Path(out)
    att, ben, ing = (pd.read_csv(out / f) for f in ("attacks.csv", "benign.csv", "ingestion.csv"))
    run = json.load(open(out / "run.json"))
    asr = asr_table(att)
    asr_j = asr_table(att, "judge_success")
    ret = retrieval_table(att)
    bt = benign_table(ben, ing)
    lt = latency_table(att, ben, ing)
    for name, df in [("asr_by_family", asr), ("asr_by_family_judge", asr_j), ("retrieval_vs_asr", ret), ("benign_utility_fpr", bt), ("latency", lt)]:
        df.to_csv(out / f"{name}.csv", index=False)
    sub = per_case(att).groupby(["config", "family", "subtype"], as_index=False).rule_success.mean()
    sub.to_csv(out / "asr_by_subtype.csv", index=False)

    configs = [c for c in att.config.unique()]
    plot_asr(asr, out / "asr_by_family.png")
    plot_heatmap(asr, out / "ablation_heatmap.png", configs)
    plot_tradeoff(asr, bt, out / "tradeoff.png")
    plot_latency(lt, out / "latency.png")

    wide = asr.assign(cell=lambda d: d.asr.map(pct)).pivot(index="config", columns="family", values="cell").reindex(configs)[FAMILIES + ["ALL"]].reset_index()
    ci_all = asr[asr.family == "ALL"].set_index("config")
    wide["ALL 95% CI"] = [f"[{ci_all.loc[c, 'lo'] * 100:.0f}, {ci_all.loc[c, 'hi'] * 100:.0f}]" for c in wide.config]
    ben_view = bt[["config", "utility", "utility_hard", "fpr_query", "quarantine_rate", "canary_leak"]]
    ret_view = ret[ret.config.isin(["none", "all"])][["config", "family", "retrieval_hit", "in_context", "asr", "asr_given_in_context"]]
    lat_view = lt[["config", "added_ms", "ingest_ms_per_doc", "ms_generate"]]
    judge_dis = (att.rule_success != att.judge_success).mean()
    md = f"""# Results - `{run['llm']}`

Embedder `{run['embedder']}`, {run['n_attacks']} attack cases, {run['n_benign']} benign queries, {run['seeds']} LLM seed(s).
ASR denominators are attack cases (seed-averaged); intervals are 95% Wilson.

## Attack success rate (rule-based)
{md_table(wide)}
![ASR](asr_by_family.png)

## Utility and false positives on benign queries
`utility` = gold answer present; `utility_hard` = on queries whose source doc has imperatives/URLs/comments;
`fpr_query` = share of benign queries where a retrieval guard dropped a chunk or the output guard changed/blocked the answer;
`quarantine_rate` = clean chunks rejected at ingestion; `canary_leak` = canary in a benign answer.
{md_table(ben_view, {c: pct for c in ben_view.columns if c != 'config'})}
![tradeoff](tradeoff.png)

## Retrieval hit rate vs attack success (none vs all)
{md_table(ret_view, {c: pct for c in ret_view.columns if c not in ('config', 'family')})}
## Added latency (ms/query excluding generation) and ingestion cost
{md_table(lat_view, {c: (lambda v: f'{v:.2f}') for c in lat_view.columns if c != 'config'})}
![latency](latency.png)

## Ablation heatmap
![heatmap](ablation_heatmap.png)

Rule vs fuzzy-judge disagreement on attack outcomes: {judge_dis * 100:.1f}% of runs.
"""
    (out / "results.md").write_text(md)
    print(f"report written to {out}/results.md")


if __name__ == "__main__":
    import sys
    make_report(Path(sys.argv[1]))
