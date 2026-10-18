import collections

from attacks.suite import build_suite


def test_suite_size_and_families(world):
    cases = build_suite(world)
    assert len(cases) == 250
    fam = collections.Counter(c.family for c in cases)
    assert set(fam) == {"injection", "retrieval", "exfiltration", "obfuscation"}
    assert all(n >= 55 for n in fam.values())
    assert len({c.case_id for c in cases}) == 250


def test_every_case_is_scoreable(world):
    for c in build_suite(world):
        assert c.poison_docs and c.owasp
        assert c.markers or c.regexes or c.canary_goal, c.case_id


def test_suite_is_deterministic(world):
    a, b = build_suite(world), build_suite(world)
    assert [x.to_dict() for x in a] == [x.to_dict() for x in b]


def test_no_gold_leak_in_wrong_answers(world):
    for c in build_suite(world):
        if c.goal == "wrong_answer":
            assert c.markers[0] not in c.gold and c.gold not in c.markers[0]
