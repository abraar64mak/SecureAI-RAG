"""Stage 1 - ingestion defenses.

  * HiddenTextStripper : comments, CSS-hidden elements, zero-width/bidi/tag
                         characters, mixed-script homoglyphs, encoded blobs
  * InjectionClassifier: TF-IDF + logistic regression on sentences (chunk score =
                         max sentence score). A Meta Prompt Guard backend is
                         available via RAG_INJ_CLASSIFIER=promptguard
  * PerplexityFilter   : character-trigram LM; flags gibberish / optimised
                         adversarial suffixes (GCG-style) with high perplexity
"""
from __future__ import annotations

import base64
import math
import os
import re
import unicodedata
from collections import Counter

import numpy as np

# --------------------------------------------------------------------------- stripper
INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f­]")
COMMENT = re.compile(r"<!--.*?-->", re.S)
HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0(?![.\d])|"
    r"color\s*:\s*(#fff\b|#ffffff\b|white\b|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))|"
    r"text-indent\s*:\s*-\d{3,}|left\s*:\s*-\d{3,}px|height\s*:\s*0(px)?\s*;?\s*overflow\s*:\s*hidden", re.I)
TAG = re.compile(r"<(/?)([a-zA-Z][\w-]*)\b([^>]*)>")
VOID = {"br", "img", "hr", "input", "meta", "link", "wbr", "source"}
B64_BLOB = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")
CONFUSABLES = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ѕ": "s", "ԁ": "d", "ο": "o", "ν": "v", "ɡ": "g", "ӏ": "l"}


class HiddenTextStripper:
    @staticmethod
    def _is_hidden(attrs: str) -> bool:
        return bool(HIDDEN_STYLE.search(attrs) or re.search(r"(^|\s)hidden(\s|=|$)|aria-hidden\s*=\s*[\"']?true", attrs, re.I))

    def _drop_hidden_elements(self, raw: str, flags: list) -> str:
        """Walk tags with a stack and drop everything inside an element whose
        attributes hide it (display:none, white-on-white, zero font, ...)."""
        out, pos, stack, hide_at = [], 0, [], None
        for m in TAG.finditer(raw):
            if hide_at is None:
                out.append(raw[pos:m.start()])
            pos = m.end()
            closing, name, attrs = m.group(1), m.group(2).lower(), m.group(3)
            if name in VOID or attrs.rstrip().endswith("/"):
                if hide_at is None:
                    out.append(m.group(0))
                continue
            if not closing:
                stack.append(name)
                if hide_at is None and self._is_hidden(attrs):
                    hide_at = len(stack)
                    flags.append("hidden_element")
                if hide_at is None:
                    out.append(m.group(0))
            else:
                if name in stack:
                    while stack[-1] != name:
                        stack.pop()
                    depth = len(stack)
                    stack.pop()
                    if hide_at is not None:
                        if depth == hide_at:
                            hide_at = None
                        continue
                if hide_at is None:
                    out.append(m.group(0))
        if hide_at is None:
            out.append(raw[pos:])
        return "".join(out)

    def __call__(self, raw: str, fmt: str = "txt") -> tuple[str, list[str]]:
        flags = []
        if COMMENT.search(raw):
            flags.append("html_comment")
            raw = COMMENT.sub(" ", raw)

        raw = self._drop_hidden_elements(raw, flags)
        if INVISIBLE.search(raw):
            flags.append("invisible_chars")
            raw = INVISIBLE.sub("", raw)

        def fix_word(m):
            w = m.group(0)
            if any(ch in CONFUSABLES for ch in w) and any(ch.isascii() and ch.isalpha() for ch in w):
                flags.append("homoglyph")
                return "".join(CONFUSABLES.get(ch, ch) for ch in w)
            return w

        raw = re.sub(r"\w+", fix_word, raw)
        raw = unicodedata.normalize("NFKC", raw)

        def drop_blob(m):
            blob = m.group(0)
            try:
                dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
            except Exception:
                return blob
            if dec.isprintable() and sum(c.isalpha() or c == " " for c in dec) / max(1, len(dec)) > 0.6:
                flags.append("encoded_blob")
                return " [removed-encoded-content] "
            return blob

        raw = B64_BLOB.sub(drop_blob, raw)
        return raw, sorted(set(flags))


# --------------------------------------------------------------------------- classifier
def _sentences(text: str) -> list[str]:
    out = [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", text) if len(s.strip()) > 3]
    return out or [text]


class InjectionClassifier:
    name = "tfidf-lr"

    def __init__(self, threshold: float = 0.5, seed: int = 3):
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import make_pipeline

        from defenses.clf_data import build_training_set

        X, y = build_training_set(seed)
        self.model = make_pipeline(
            TfidfVectorizer(ngram_range=(1, 3), sublinear_tf=True, lowercase=True),
            LogisticRegression(C=8.0, max_iter=2000, class_weight="balanced"),
        ).fit(X, y)
        self.threshold = threshold

    def score(self, text: str) -> float:
        sents = _sentences(text)
        return float(self.model.predict_proba(sents)[:, 1].max())

    def flag(self, text: str) -> bool:
        return self.score(text) >= self.threshold


class PromptGuardClassifier:
    """Meta Prompt Guard 86M (gated on HF; accept the licence and `huggingface-cli login`)."""
    name = "prompt-guard"

    def __init__(self, threshold: float = 0.5, model: str = "meta-llama/Prompt-Guard-86M"):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.tok = AutoTokenizer.from_pretrained(model)
        self.m = AutoModelForSequenceClassification.from_pretrained(model).eval()
        self.torch = torch
        self.threshold = threshold

    def score(self, text: str) -> float:
        best = 0.0
        for s in _sentences(text):
            enc = self.tok(s, return_tensors="pt", truncation=True, max_length=512)
            with self.torch.no_grad():
                p = self.torch.softmax(self.m(**enc).logits, -1)[0]
            best = max(best, float(1 - p[0]))  # label 0 = BENIGN
        return best

    def flag(self, text: str) -> bool:
        return self.score(text) >= self.threshold


def get_classifier():
    if os.environ.get("RAG_INJ_CLASSIFIER") == "promptguard":
        return PromptGuardClassifier()
    return InjectionClassifier()


# --------------------------------------------------------------------------- perplexity
class PerplexityFilter:
    """Character trigram LM with add-k smoothing. The threshold is calibrated on
    held-out clean chunks (default: 99th percentile -> ~1% chunk-level FPR)."""

    def __init__(self, order: int = 3, k: float = 0.1, pct: float = 99.0):
        self.n, self.k, self.pct = order, k, pct
        self.threshold = math.inf

    def _grams(self, t: str):
        t = "^" * (self.n - 1) + re.sub(r"\s+", " ", t.lower())
        for i in range(len(t) - self.n + 1):
            yield t[i:i + self.n - 1], t[i + self.n - 1]

    def fit(self, train: list[str], calib: list[str]) -> "PerplexityFilter":
        self.ctx, self.cnt = Counter(), Counter()
        self.vocab = set()
        for t in train:
            for c, ch in self._grams(t):
                self.ctx[c] += 1
                self.cnt[(c, ch)] += 1
                self.vocab.add(ch)
        self.V = len(self.vocab) + 1
        scores = [self.perplexity(t) for t in calib]
        self.threshold = float(np.percentile(scores, self.pct)) if scores else math.inf
        return self

    def perplexity(self, text: str) -> float:
        lp, n = 0.0, 0
        for c, ch in self._grams(text):
            lp += math.log((self.cnt.get((c, ch), 0) + self.k) / (self.ctx.get(c, 0) + self.k * self.V))
            n += 1
        return math.exp(-lp / max(1, n))

    def flag(self, text: str) -> bool:
        return self.perplexity(text) > self.threshold
