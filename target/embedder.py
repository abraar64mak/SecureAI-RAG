"""Embedding backends.

`lsa` (default): TF-IDF + truncated SVD. Dependency-light and works offline, so
the whole suite runs in CI. `st`: sentence-transformers (set RAG_EMBEDDER=st
and RAG_ST_MODEL, default all-MiniLM-L6-v2). Both return L2-normalised float32
vectors so inner product == cosine similarity.
"""
from __future__ import annotations

import os

import numpy as np


class LSAEmbedder:
    name = "lsa"

    def __init__(self, dim: int = 256):
        self.dim = dim
        self._fitted = False

    def fit(self, texts: list[str]) -> "LSAEmbedder":
        from sklearn.decomposition import TruncatedSVD
        from sklearn.feature_extraction.text import TfidfVectorizer

        self.vec = TfidfVectorizer(sublinear_tf=True, ngram_range=(1, 2), stop_words="english", token_pattern=r"(?u)\b[\w'-]{2,}\b")
        X = self.vec.fit_transform(texts)
        k = max(2, min(self.dim, X.shape[1] - 1, X.shape[0] - 1))
        self.svd = TruncatedSVD(k, random_state=0).fit(X)
        self.dim = k
        self._fitted = True
        return self

    def encode(self, texts: list[str]) -> np.ndarray:
        Z = self.svd.transform(self.vec.transform(texts)).astype("float32")
        n = np.linalg.norm(Z, axis=1, keepdims=True)
        n[n == 0] = 1.0
        return Z / n


class STEmbedder:
    name = "st"

    def __init__(self, model: str | None = None):
        from sentence_transformers import SentenceTransformer  # lazy import

        self.model = SentenceTransformer(model or os.environ.get("RAG_ST_MODEL", "sentence-transformers/all-MiniLM-L6-v2"))
        self.dim = self.model.get_sentence_embedding_dimension()

    def fit(self, texts: list[str]) -> "STEmbedder":
        return self  # pre-trained

    def encode(self, texts: list[str]) -> np.ndarray:
        return self.model.encode(texts, normalize_embeddings=True, show_progress_bar=False).astype("float32")


def get_embedder(name: str | None = None):
    name = name or os.environ.get("RAG_EMBEDDER", "lsa")
    if name == "st":
        return STEmbedder()
    return LSAEmbedder()
