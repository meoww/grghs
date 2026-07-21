from seedleak.collectors.queries import (
    CODE_CONSTRUCT_QUERIES,
    build_bip39_ngram_queries,
    default_hunt_queries,
)


def test_default_catalog_has_code_and_ngrams():
    qs = default_hunt_queries(ngram_count=20)
    cats = {q.category for q in qs}
    assert "code" in cats
    assert "env" in cats
    assert "bip39_ngram" in cats
    assert len(qs) > len(CODE_CONSTRUCT_QUERIES)
    # All queries non-empty
    assert all(q.query.strip() for q in qs)


def test_ngrams_are_quoted_phrases():
    qs = build_bip39_ngram_queries(n=3, count=10)
    assert len(qs) == 10
    for q in qs:
        assert q.query.startswith('"')
        assert "mnemonic OR seed OR wallet" in q.query or "mnemonic" in q.query
