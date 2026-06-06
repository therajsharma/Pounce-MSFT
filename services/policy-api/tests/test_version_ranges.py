from __future__ import annotations

import pytest

from pounce_sentinel import version_ranges


@pytest.mark.parametrize(
    ("version", "spec", "expected"),
    [
        # caret
        ("1.2.3", "^1.2.3", True),
        ("1.5.0", "^1.2.3", True),
        ("2.0.0", "^1.2.3", False),
        ("1.2.2", "^1.2.3", False),
        ("0.2.5", "^0.2.3", True),  # ^0.x pins minor
        ("0.3.0", "^0.2.3", False),
        ("0.0.3", "^0.0.3", True),  # ^0.0.x pins patch
        ("0.0.4", "^0.0.3", False),
        # tilde
        ("1.2.9", "~1.2.3", True),
        ("1.3.0", "~1.2.3", False),
        ("1.2.0", "~1.2", True),
        ("1.3.0", "~1.2", False),
        # comparators / conjunction
        ("1.9.99", ">=1.0.0 <2.0.0", True),
        ("2.0.0", ">=1.0.0 <2.0.0", False),
        ("0.9.0", ">=1.0.0 <2.0.0", False),
        ("1.2.7", ">= 1.0.0, < 1.2.8", True),  # GHSA-style spaces + comma
        ("1.2.8", ">= 1.0.0, < 1.2.8", False),
        # x-ranges
        ("1.99.0", "1.x", True),
        ("2.0.0", "1.x", False),
        ("1.2.99", "1.2.x", True),
        ("1.3.0", "1.2.x", False),
        ("3.1.0", "*", True),
        # hyphen range (inclusive)
        ("2.0.0", "1.2.3 - 2.0.0", True),
        ("2.0.1", "1.2.3 - 2.0.0", False),
        # disjunction
        ("0.9.0", "<1.0.0 || >=2.0.0", True),
        ("2.5.0", "<1.0.0 || >=2.0.0", True),
        ("1.5.0", "<1.0.0 || >=2.0.0", False),
        # exact
        ("1.2.3", "1.2.3", True),
        ("1.2.4", "1.2.3", False),
        # pre-release excluded by default
        ("1.0.0-beta", "^1.0.0", False),
        ("1.2.3-beta", "1.2.3-beta", True),
    ],
)
def test_npm_satisfies(version: str, spec: str, expected: bool) -> None:
    assert version_ranges.satisfies(version, spec, ecosystem="npm") is expected


@pytest.mark.parametrize(
    ("version", "spec", "expected"),
    [
        ("2.32.5", ">=2.0", True),
        ("1.9.0", ">=2.0", False),
        ("2.32.5", "~=2.32", True),  # compatible release: >=2.32, <3.0
        ("3.0.0", "~=2.32", False),
        ("1.4.7", "~=1.4.5", True),  # >=1.4.5, <1.5.0
        ("1.5.0", "~=1.4.5", False),
        ("2.32.5", "==2.32.*", True),
        ("2.33.0", "==2.32.*", False),
        ("2.0.0", "!=2.30.0,>=2.0", True),
        ("2.30.0", "!=2.30.0,>=2.0", False),
        ("1.0.0", "===1.0.0", True),
        ("1.0.0", "===1.0.1", False),
        ("2.32.5", ">2.0,<3.0", True),
        ("3.1.0", ">2.0,<3.0", False),
    ],
)
def test_pypi_satisfies(version: str, spec: str, expected: bool) -> None:
    assert version_ranges.satisfies(version, spec, ecosystem="pypi") is expected


def test_garbage_spec_returns_false_never_raises() -> None:
    assert version_ranges.satisfies("1.2.3", ">>not a spec<<", ecosystem="npm") is False
    assert version_ranges.satisfies("1.2.3", "", ecosystem="npm") is True  # empty == any
    assert version_ranges.satisfies("nonsense", "^1.0.0", ecosystem="npm") is False
    assert version_ranges.satisfies("1.2.3", "^1.0.0", ecosystem="maven") is False  # unknown ecosystem
