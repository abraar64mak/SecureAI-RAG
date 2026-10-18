"""Write the synthetic corpus, benign queries and attack suite to data/ (all public, all synthetic)."""
import json
from pathlib import Path

from attacks.suite import build_suite, save_suite
from target.corpus import save_corpus
from target.rag import World


def main():
    w = World()
    d = Path("data"); d.mkdir(exist_ok=True)
    save_corpus(w.corpus, d / "corpus.jsonl")
    with open(d / "benign_queries.jsonl", "w") as f:
        for b in w.benign:
            f.write(json.dumps(b.__dict__) + "\n")
    save_suite(build_suite(w))
    with open(d / "canaries.json", "w") as f:
        json.dump([c.__dict__ for c in w.corpus.canaries], f, indent=1)
    print("wrote", sorted(p.name for p in d.iterdir()))


if __name__ == "__main__":
    main()
