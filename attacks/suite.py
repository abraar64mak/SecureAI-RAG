"""Build, save and load the full attack suite (250 cases)."""
from __future__ import annotations

import json
import random
from pathlib import Path

from attacks import exfiltration, injection, obfuscation, retrieval
from attacks.base import AttackCase, FactPicker

SUITE_PATH = Path(__file__).resolve().parent.parent / "data" / "attack_suite.jsonl"


def build_suite(world, seed: int = 21) -> list[AttackCase]:
    rng = random.Random(seed)
    picker = FactPicker(world.corpus, rng)
    cases = injection.generate(world.corpus, rng, picker)
    cases += retrieval.generate(world, rng, picker, per_subtype=15)
    cases += exfiltration.generate(world.corpus, rng, picker)
    cases += obfuscation.generate(world.corpus, rng, picker)
    return cases


def save_suite(cases: list[AttackCase], path: Path = SUITE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for c in cases:
            f.write(json.dumps(c.to_dict(), ensure_ascii=False) + "\n")


def load_suite(path: Path = SUITE_PATH) -> list[AttackCase]:
    return [AttackCase.from_dict(json.loads(l)) for l in open(path)]
