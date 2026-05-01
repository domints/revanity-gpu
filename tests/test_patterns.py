from revanity_gpu.config import MatchMode
from revanity_gpu.patterns import CompiledPattern, estimate_difficulty, validate_hex_pattern


def test_validate_hex_pattern():
    assert validate_hex_pattern(" DeAd ") == "dead"


def test_compiled_prefix():
    cp = CompiledPattern.compile(MatchMode.PREFIX, "dead")
    assert cp.matches_hex("deadbeef" + "0" * 24)
    assert not cp.matches_hex("beefdead" + "0" * 24)


def test_regex():
    cp = CompiledPattern.compile(MatchMode.REGEX, "^(dead|beef)")
    assert cp.matches_hex("beef" + "0" * 28)
    assert not cp.matches_hex("cafe" + "0" * 28)


def test_difficulty():
    d = estimate_difficulty(MatchMode.PREFIX, "dead")
    assert d.can_estimate
    assert d.expected_attempts > 0
