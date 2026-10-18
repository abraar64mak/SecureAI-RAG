"""Assemble the toggleable layers for a DefenseConfig."""
from __future__ import annotations

from dataclasses import dataclass

from defenses.config import DefenseConfig
from defenses.ingestion import HiddenTextStripper, PerplexityFilter, get_classifier
from defenses.output import OutputGuard
from defenses.prompt import PromptDefense
from defenses.retrieval import RetrievalGuard

_CLF = None


def shared_classifier():
    global _CLF
    if _CLF is None:
        _CLF = get_classifier()
    return _CLF


@dataclass
class DefenseSuite:
    cfg: DefenseConfig
    stripper: HiddenTextStripper | None
    clf: object | None
    ppl: PerplexityFilter | None
    retrieval: RetrievalGuard | None
    prompt: PromptDefense | None
    output: OutputGuard | None


def build_suite(cfg: DefenseConfig, canaries, ppl: PerplexityFilter | None, sim_threshold: float, judge=None) -> DefenseSuite:
    return DefenseSuite(
        cfg=cfg,
        stripper=HiddenTextStripper() if cfg.strip_hidden else None,
        clf=shared_classifier() if cfg.injection_clf else None,
        ppl=ppl if cfg.perplexity else None,
        retrieval=RetrievalGuard(cfg.outlier, cfg.dedup, sim_threshold) if cfg.retrieval else None,
        prompt=PromptDefense(cfg.spotlight, cfg.hierarchy) if cfg.prompt else None,
        output=OutputGuard(canaries, cfg.canary_scan, cfg.url_allowlist, cfg.strip_images, cfg.output_judge, judge) if cfg.output else None,
    )
