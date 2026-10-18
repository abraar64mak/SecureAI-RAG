"""The RAG system under test: ingestion -> FAISS retrieval -> prompt -> LLM -> output.

`World` holds everything that is shared across defense configurations (corpus,
fitted embedder, calibration, base-index cache). `RAGSystem` is one configured
system. Every stage is timed so added latency per layer can be reported.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import numpy as np

from defenses.config import DefenseConfig
from defenses.ingestion import PerplexityFilter
from defenses.prompt import unmark
from defenses.retrieval import RetrievalGuard
from defenses.suite import build_suite
from target.corpus import Corpus, Document, build_corpus
from target.embedder import get_embedder
from target.index import Chunk, VectorIndex, chunk_text, extract_text
from target.llm import get_llm
from target.prompts import build_baseline
from target.queries import build_benign_queries

TOP_K = 5


@dataclass
class IngestReport:
    doc_id: str
    chunk_ids: list[int]
    n_chunks: int
    quarantined: int
    flags: list[str]
    ms: float


@dataclass
class RAGResult:
    query: str
    answer: str
    raw_answer: str
    raw_hits: list[tuple[str, str, float]]  # (doc_id, source, score) from FAISS top-k, pre-guard
    context_docs: list[str]
    flags: list[str]
    latency: dict
    system: str = ""
    user: str = ""


class World:
    def __init__(self, embedder: str | None = None, seed: int = 7):
        self.corpus: Corpus = build_corpus(seed)
        self.benign, self.calib_queries = build_benign_queries(self.corpus)
        self.canaries = self.corpus.canaries
        self.system_canary = next(c.value for c in self.canaries if c.kind == "system_prompt")
        self.embedder = get_embedder(embedder)
        # fit the embedder on clean, undefended chunk text
        texts = [t for d in self.corpus.docs for t in chunk_text(extract_text(d.text, d.fmt))]
        self.embedder.fit(texts)
        # perplexity LM: train on 2/3 of docs, calibrate on the held-out third
        train, calib = [], []
        for i, d in enumerate(self.corpus.docs):
            (calib if i % 3 == 0 else train).extend(chunk_text(extract_text(d.text, d.fmt)))
        self.ppl = PerplexityFilter().fit(train, calib)
        self._base_cache: dict[tuple, tuple] = {}
        self.sim_threshold = 0.8  # replaced after calibration below
        base_idx, _ = self.base_index(DefenseConfig())
        self.sim_threshold = RetrievalGuard.calibrate(base_idx, self.embedder, self.calib_queries)

    # ------------------------------------------------------------------ index
    def base_index(self, cfg: DefenseConfig):
        """Index of the clean corpus built under the config's ingestion toggles (cached)."""
        key = cfg.ingestion_key()
        if key not in self._base_cache:
            sys_ = RAGSystem(self, cfg, get_llm("sim:llama-like"), _build=False)
            idx = VectorIndex(self.embedder.dim)
            sys_.index = idx
            stats = {"docs": 0, "chunks": 0, "quarantined": 0, "flagged_docs": 0, "ms": 0.0}
            for d in self.corpus.docs:
                r = sys_.ingest(d)
                stats["docs"] += 1
                stats["chunks"] += r.n_chunks
                stats["quarantined"] += r.quarantined
                stats["flagged_docs"] += bool(r.flags)
                stats["ms"] += r.ms
            self._base_cache[key] = (idx, stats)
        return self._base_cache[key]


class RAGSystem:
    def __init__(self, world: World, cfg: DefenseConfig, llm, judge=None, _build: bool = True):
        self.world, self.cfg, self.llm = world, cfg, llm
        self.suite = build_suite(cfg, world.canaries, world.ppl, world.sim_threshold, judge)
        if _build:
            self.index, self.base_stats = world.base_index(cfg)

    # ------------------------------------------------------------------ ingest
    def ingest(self, doc: Document) -> IngestReport:
        t0 = time.perf_counter()
        raw, flags = doc.text, []
        if self.suite.stripper:
            raw, f = self.suite.stripper(raw, doc.fmt)
            flags += [f"ing:strip:{x}" for x in f]
        chunks_txt = chunk_text(extract_text(raw, doc.fmt))
        kept, quarantined = [], 0
        for i, t in enumerate(chunks_txt):
            if self.suite.clf is not None and self.suite.clf.flag(t):
                flags.append(f"ing:clf:{doc.doc_id}")
                quarantined += 1
                continue
            if self.suite.ppl is not None and self.suite.ppl.flag(t):
                flags.append(f"ing:ppl:{doc.doc_id}")
                quarantined += 1
                continue
            kept.append((i, t))
        chunks = [Chunk(self.index.new_id(), doc.doc_id, i, t, doc.source) for i, t in kept]
        if chunks:
            self.index.add(chunks, self.world.embedder.encode([c.text for c in chunks]))
        return IngestReport(doc.doc_id, [c.chunk_id for c in chunks], len(chunks_txt), quarantined, flags, (time.perf_counter() - t0) * 1000)

    def remove(self, report: IngestReport) -> None:
        self.index.remove(report.chunk_ids)

    # ------------------------------------------------------------------ query
    def answer(self, query: str) -> RAGResult:
        lat, flags = {}, []
        t = time.perf_counter()
        qv = self.world.embedder.encode([query])[0]
        lat["embed"] = (time.perf_counter() - t) * 1000

        t = time.perf_counter()
        pool = TOP_K * 2 if self.suite.retrieval else TOP_K
        hits = self.index.search(qv, pool)
        lat["search"] = (time.perf_counter() - t) * 1000
        raw_hits = [(c.doc_id, c.source, s) for c, s in hits[:TOP_K]]

        t = time.perf_counter()
        if self.suite.retrieval:
            hits, f = self.suite.retrieval.filter(query, hits, self.index.vecs)
            flags += f
        hits = hits[:TOP_K]
        lat["retrieval_guard"] = (time.perf_counter() - t) * 1000

        chunks = [c for c, _ in hits]
        t = time.perf_counter()
        if self.suite.prompt:
            system, user = self.suite.prompt.build(self.world.system_canary, chunks, query)
        else:
            system, user = build_baseline(self.world.system_canary, chunks, query)
        lat["prompt"] = (time.perf_counter() - t) * 1000

        t = time.perf_counter()
        raw = self.llm.generate(system, user)
        lat["generate"] = (time.perf_counter() - t) * 1000
        raw = unmark(raw) if self.suite.prompt else raw

        t = time.perf_counter()
        out = raw
        if self.suite.output:
            out, f = self.suite.output.apply(query, raw)
            flags += f
        lat["output_guard"] = (time.perf_counter() - t) * 1000
        return RAGResult(query, out, raw, raw_hits, [c.doc_id for c in chunks], flags, lat, system, user)
