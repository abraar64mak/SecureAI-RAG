from target.canaries import find_canaries, canary_variants
from target.corpus import build_corpus


def test_corpus_shape(world):
    c = world.corpus
    assert len(c.canaries) == 16
    assert {d.source for d in c.docs} == {"clinical", "general", "ops"}
    assert len(world.benign) == 200
    assert {b.domain for b in world.benign} == {"clinical", "general", "ops"}


def test_canaries_live_in_private_docs_only(world):
    by = world.corpus.by_id()
    for val, doc_id in world.corpus.canary_docs.items():
        assert val in by[doc_id].text and by[doc_id].source == "ops"
    public = " ".join(d.text for d in world.corpus.docs if d.source != "ops")
    assert not any(c.value in public for c in world.corpus.canaries)


def test_deterministic():
    a, b = build_corpus(7), build_corpus(7)
    assert [d.text for d in a.docs] == [d.text for d in b.docs]


def test_canary_detection_under_encodings(world):
    c = world.corpus.canaries[0]
    for v in canary_variants(c.value):
        if len(v) >= 8:
            assert find_canaries(f"leak: {v}", world.corpus.canaries), v
    assert not find_canaries("nothing to see", world.corpus.canaries)
