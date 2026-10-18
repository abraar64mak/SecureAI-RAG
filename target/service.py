"""FastAPI wrapper around the RAG system.

    RAG_LLM=ollama:llama3.1:8b uvicorn target.service:app --port 8000
    curl -s localhost:8000/query -d '{"question":"What is the maximum daily dose of Zorvanil?","defenses":"all"}' -H 'content-type: application/json'

`defenses` is any preset name from defenses.config (none, ingestion, ..., all, all-minus-output).
This is also the endpoint to point external scanners (garak, promptfoo) at.
"""
from __future__ import annotations

import os
from functools import lru_cache

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from defenses.config import ALL_CONFIGS, SUBLAYER_CONFIGS, preset
from target.corpus import Document
from target.llm import get_llm
from target.rag import RAGSystem, World

app = FastAPI(title="SecureAI-RAG target", version="1.0")


@lru_cache(maxsize=1)
def world() -> World:
    return World()


@lru_cache(maxsize=1)
def llm():
    return get_llm(os.environ.get("RAG_LLM", "sim:llama-like"))


_systems: dict[str, RAGSystem] = {}


def system(name: str) -> RAGSystem:
    if name not in _systems:
        try:
            cfg = preset(name)
        except KeyError:
            raise HTTPException(400, f"unknown defense preset {name!r}")
        _systems[name] = RAGSystem(world(), cfg, llm())
    return _systems[name]


class Query(BaseModel):
    question: str
    defenses: str = "all"


class Ingest(BaseModel):
    doc_id: str
    text: str
    fmt: str = "txt"
    defenses: str = "all"


@app.get("/health")
def health():
    return {"status": "ok", "llm": llm().name, "embedder": world().embedder.name}


@app.get("/configs")
def configs():
    return {"presets": ALL_CONFIGS, "sublayers": SUBLAYER_CONFIGS}


@app.post("/query")
def query(q: Query):
    r = system(q.defenses).answer(q.question)
    return {"answer": r.answer, "sources": r.context_docs, "flags": r.flags,
            "latency_ms": {k: round(v, 3) for k, v in r.latency.items()}}


@app.post("/ingest")
def ingest(d: Ingest):
    r = system(d.defenses).ingest(Document(d.doc_id, d.doc_id, d.text, d.fmt, "user"))
    return {"doc_id": r.doc_id, "chunks": r.n_chunks, "quarantined": r.quarantined, "flags": r.flags, "ms": round(r.ms, 2)}
