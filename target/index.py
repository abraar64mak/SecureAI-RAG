"""Chunking, text extraction and the FAISS index."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import faiss
import numpy as np


@dataclass
class Chunk:
    chunk_id: int
    doc_id: str
    idx: int
    text: str
    source: str  # clinical | general | ops | poison
    meta: dict = field(default_factory=dict)


def extract_text(raw: str, fmt: str) -> str:
    """Baseline (undefended) loader.

    html: drop script/style blocks and every tag (this also drops comments) but
          keep the text of elements hidden with CSS, as a naive tag-stripper does.
    md/txt: kept verbatim, so HTML comments and inline HTML survive.
    """
    if fmt == "html":
        raw = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", raw)
        raw = re.sub(r"<[^>]+>", " ", raw)
    return re.sub(r"[ \t]+", " ", re.sub(r"\n\s*\n+", "\n\n", raw)).strip()


def chunk_text(text: str, size: int = 110, stride: int = 90) -> list[str]:
    words = text.split()
    if len(words) <= size:
        return [text]
    return [" ".join(words[i:i + size]) for i in range(0, max(1, len(words) - (size - stride)), stride)]


class VectorIndex:
    """Exact inner-product FAISS index with id-based add/remove so poisoned
    chunks can be inserted and withdrawn per attack case."""

    def __init__(self, dim: int):
        self.dim = dim
        self.index = faiss.IndexIDMap2(faiss.IndexFlatIP(dim))
        self.chunks: dict[int, Chunk] = {}
        self.vecs: dict[int, np.ndarray] = {}
        self._next = 0

    def new_id(self) -> int:
        self._next += 1
        return self._next

    def add(self, chunks: list[Chunk], vecs: np.ndarray) -> None:
        if not chunks:
            return
        ids = np.array([c.chunk_id for c in chunks], dtype="int64")
        self.index.add_with_ids(np.ascontiguousarray(vecs, dtype="float32"), ids)
        for c, v in zip(chunks, vecs):
            self.chunks[c.chunk_id] = c
            self.vecs[c.chunk_id] = v

    def remove(self, chunk_ids: list[int]) -> None:
        if not chunk_ids:
            return
        self.index.remove_ids(np.array(chunk_ids, dtype="int64"))
        for i in chunk_ids:
            self.chunks.pop(i, None)
            self.vecs.pop(i, None)

    def search(self, qvec: np.ndarray, k: int) -> list[tuple[Chunk, float]]:
        if self.index.ntotal == 0:
            return []
        scores, ids = self.index.search(np.ascontiguousarray(qvec.reshape(1, -1), dtype="float32"), k)
        return [(self.chunks[int(i)], float(s)) for i, s in zip(ids[0], scores[0]) if i != -1]
