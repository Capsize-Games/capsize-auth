"""PKCE verifier and challenge generation."""

from capsize_auth.oauth2 import pkce


def test_a_pair_verifies() -> None:
    pair = pkce.generate()
    assert pkce.verify(pair.verifier, pair.challenge)
    assert pair.method == "S256"


def test_the_challenge_is_unpadded_base64url() -> None:
    pair = pkce.generate()
    assert "=" not in pair.challenge
    assert "+" not in pair.challenge and "/" not in pair.challenge


def test_a_wrong_verifier_does_not_verify() -> None:
    pair = pkce.generate()
    assert not pkce.verify(pkce.generate().verifier, pair.challenge)


def test_the_challenge_matches_the_rfc_example() -> None:
    # RFC 7636 appendix B's worked example.
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert pkce.challenge_for(verifier) == expected
