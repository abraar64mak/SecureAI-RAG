"""Stage 2 - retrieval defenses.

  * outlier : a chunk is suspicious if its similarity to the query exceeds a
              threshold calibrated on benign queries (suspiciously good match),
              or if it contains the entire question verbatim (query mirroring).
  * dedup   : drops near-duplicate chunks inside the top-k (multi-copy poisoning)
              and chunks with a very low unique-token ratio (keyword stuffing).
Flagged chunks are removed from the context before prompt construction.
"""
from __future__ import annotations

import re

import numpy as np


def _norm_tokens(s: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", s.lower())


def _contains_question(chunk: str, query: str) -> bool:
    q = _norm_tokens(query)
    if len(q) < 4:
        return False
    c = " " + " ".join(_norm_tokens(chunk)) + " "
    return (" " + " ".join(q) + " ") in c


def unique_ratio(text: str) -> float:
    t = [w for w in _norm_tokens(text) if len(w) >= 3]
    return len(set(t)) / len(t) if len(t) >= 30 else 1.0


class RetrievalGuard:
    def __init__(self, outlier: bool, dedup: bool, sim_threshold: float = 0.8, dup_threshold: float = 0.97, ur_threshold: float = 0.5):
        self.outlier, self.dedup = outlier, dedup
        self.sim_threshold, self.dup_threshold, self.ur_threshold = sim_threshold, dup_threshold, ur_threshold

    @staticmethod
    def calibrate(index, embedder, calib_queries: list[str], pct: float = 99.0) -> float:
        """Threshold = pct-th percentile of top-1 similarity over held-out benign queries."""
        q = embedder.encode(calib_queries)
        tops = [index.search(v, 1)[0][1] for v in q]
        return float(np.percentile(tops, pct))

    def filter(self, query: str, hits: list[tuple], vecs: dict) -> tuple[list[tuple], list[str]]:
        """hits: [(Chunk, score)] in rank order. Returns (kept, flags)."""
        kept, flags = [], []
        for chunk, score in hits:
            if self.outlier:
                if score > self.sim_threshold:
                    flags.append(f"retr:high_sim:{chunk.doc_id}")
                    continue
                if _contains_question(chunk.text, query):
                    flags.append(f"retr:mirror:{chunk.doc_id}")
                    continue
            if self.dedup:
                if unique_ratio(chunk.text) < self.ur_threshold:
                    flags.append(f"retr:stuffing:{chunk.doc_id}")
                    continue
                v = vecs[chunk.chunk_id]
                if any(float(v @ vecs[k.chunk_id]) > self.dup_threshold for k, _ in kept):
                    flags.append(f"retr:duplicate:{chunk.doc_id}")
                    continue
            kept.append((chunk, score))
        return kept, flags
