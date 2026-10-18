"""Defense configuration: every layer and sub-layer is independently toggleable."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace


@dataclass(frozen=True)
class DefenseConfig:
    name: str = "none"
    # Stage 1 - ingestion
    strip_hidden: bool = False      # comments, CSS-hidden text, zero-width/bidi chars, homoglyphs, encoded blobs
    injection_clf: bool = False     # injection classifier on chunks
    perplexity: bool = False        # character-LM perplexity filter
    # Stage 2 - retrieval
    outlier: bool = False           # suspiciously-high query similarity / verbatim query mirroring
    dedup: bool = False             # near-duplicate + keyword-stuffing detection
    # Stage 3 - prompt construction
    spotlight: str = "none"         # none | delimit | datamark
    hierarchy: bool = False         # instruction-hierarchy system prompt
    # Stage 4 - output
    canary_scan: bool = False
    url_allowlist: bool = False
    strip_images: bool = False
    output_judge: bool = False

    @property
    def ingestion(self) -> bool:
        return self.strip_hidden or self.injection_clf or self.perplexity

    @property
    def retrieval(self) -> bool:
        return self.outlier or self.dedup

    @property
    def prompt(self) -> bool:
        return self.spotlight != "none" or self.hierarchy

    @property
    def output(self) -> bool:
        return self.canary_scan or self.url_allowlist or self.strip_images or self.output_judge

    def ingestion_key(self) -> tuple:
        """The base index only depends on ingestion toggles, so it can be cached."""
        return (self.strip_hidden, self.injection_clf, self.perplexity)

    def asdict(self) -> dict:
        return asdict(self)


STAGE_FLAGS = {
    "ingestion": dict(strip_hidden=True, injection_clf=True, perplexity=True),
    "retrieval": dict(outlier=True, dedup=True),
    "prompt": dict(spotlight="datamark", hierarchy=True),
    "output": dict(canary_scan=True, url_allowlist=True, strip_images=True, output_judge=True),
}


def preset(name: str) -> DefenseConfig:
    """none | ingestion | retrieval | prompt | output | all | all-minus-<stage> | <stage>:<sublayer>"""
    if name == "none":
        return DefenseConfig("none")
    if name in STAGE_FLAGS:
        return DefenseConfig(name, **STAGE_FLAGS[name])
    if name == "all":
        kw = {}
        for v in STAGE_FLAGS.values():
            kw.update(v)
        return DefenseConfig("all", **kw)
    if name.startswith("all-minus-"):
        stage = name.removeprefix("all-minus-")
        base = preset("all")
        off = {k: (False if isinstance(v, bool) else "none") for k, v in STAGE_FLAGS[stage].items()}
        return replace(base, name=name, **off)
    if ":" in name:  # single sub-layer, e.g. ingestion:strip_hidden
        _, sub = name.split(":", 1)
        val = "datamark" if sub == "spotlight" else True
        return DefenseConfig(name, **{sub: val})
    raise KeyError(name)


ALL_CONFIGS = [
    "none", "ingestion", "retrieval", "prompt", "output", "all",
    "all-minus-ingestion", "all-minus-retrieval", "all-minus-prompt", "all-minus-output",
]
SUBLAYER_CONFIGS = [
    "ingestion:strip_hidden", "ingestion:injection_clf", "ingestion:perplexity",
    "retrieval:outlier", "retrieval:dedup",
    "prompt:spotlight", "prompt:hierarchy",
    "output:canary_scan", "output:url_allowlist", "output:strip_images", "output:output_judge",
]
