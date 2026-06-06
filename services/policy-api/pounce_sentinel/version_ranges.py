"""Stdlib-only version-range satisfaction for npm semver and PyPI PEP 440.

This replaces the previous exact-`=`-only `_range_matches` so that ingested
advisory ranges (e.g. ">= 1.0.0, < 1.2.8", "^1.0.0", "~=2.32") actually match a
requested version. The public entry point is :func:`satisfies`; on any parse
failure it returns ``False`` (fail-safe — never raises), preserving the prior
behaviour for specs we cannot interpret.
"""

from __future__ import annotations

import re

_RELEASE_RE = re.compile(r"^(\d+(?:\.\d+)*)(.*)$")
_PEP440_OPS = ("===", "==", ">=", "<=", "~=", "!=", ">", "<")
_NPM_OPS = (">=", "<=", "!=", ">", "<", "=")


def satisfies(version: str, spec: str, *, ecosystem: str) -> bool:
    """Return True when ``version`` satisfies ``spec`` for the given ecosystem."""
    try:
        normalized_spec = str(spec or "").strip()
        if normalized_spec in {"", "*"}:
            return True
        eco = str(ecosystem or "").strip().lower()
        if eco == "npm":
            return _npm_satisfies(version, normalized_spec)
        if eco == "pypi":
            return _pypi_satisfies(version, normalized_spec)
        return False
    except Exception:
        return False


# --- version parsing / comparison -------------------------------------------------


def _release_and_suffix(version: str) -> tuple[int, list[int], str] | None:
    text = str(version or "").strip().lstrip("vV=").strip()
    text = text.split("+", 1)[0]  # drop build metadata
    epoch = 0
    if "!" in text:
        epoch_str, _, text = text.partition("!")
        epoch = int(epoch_str) if epoch_str.isdigit() else 0
    match = _RELEASE_RE.match(text)
    if not match:
        return None
    release = [int(part) for part in match.group(1).split(".")]
    return epoch, release, match.group(2).strip()


def _suffix_key(suffix: str) -> tuple[int, ...]:
    s = suffix.lower().lstrip("-_.").strip()
    if s == "":
        return (1,)  # final release ranks above pre-releases, below post-releases
    if s.startswith("post"):
        return (2, int(re.sub(r"\D", "", s) or "0"))
    if "dev" in s:
        return (0, 0, int(re.sub(r"\D", "", s) or "0"))
    order = {"a": 1, "alpha": 1, "b": 2, "beta": 2, "c": 3, "rc": 3, "pre": 3, "preview": 3}
    m = re.match(r"^([a-z]+)\.?(\d*)", s)
    label = m.group(1) if m else s
    num = int(m.group(2)) if (m and m.group(2)) else 0
    return (0, order.get(label, 0), num)


def _compare(left: str, right: str) -> int:
    pa = _release_and_suffix(left)
    pb = _release_and_suffix(right)
    if pa is None or pb is None:
        return (left > right) - (left < right)
    ea, ra, sa = pa
    eb, rb, sb = pb
    if ea != eb:
        return (ea > eb) - (ea < eb)
    width = max(len(ra), len(rb))
    ra = ra + [0] * (width - len(ra))
    rb = rb + [0] * (width - len(rb))
    if ra != rb:
        return (ra > rb) - (ra < rb)
    ka, kb = _suffix_key(sa), _suffix_key(sb)
    return (ka > kb) - (ka < kb)


def _cmp_tuple(version: str, release: list[int]) -> int:
    return _compare(version, ".".join(str(part) for part in release))


def _is_prerelease(version: str) -> bool:
    parsed = _release_and_suffix(version)
    return bool(parsed and parsed[2] and _suffix_key(parsed[2])[0] == 0)


# --- npm semver -------------------------------------------------------------------


def _npm_satisfies(version: str, spec: str) -> bool:
    if "||" in spec:
        return any(_npm_satisfies(version, part) for part in spec.split("||"))
    if " - " in spec:
        low, _, high = spec.partition(" - ")
        return _cmp_tuple(version, _release_or_zero(low)) >= 0 and _compare(version, high.strip().lstrip("vV")) <= 0
    comparators = _split_comparators(spec)
    if not comparators:
        return True
    if _is_prerelease(version) and not any("-" in comparator for comparator in comparators):
        # npm excludes pre-releases unless the spec itself names one (or matches exactly)
        return _compare(version, version) == 0 and all(c.lstrip("=") == version for c in comparators)
    return all(_npm_comparator(version, comparator) for comparator in comparators)


def _split_comparators(spec: str) -> list[str]:
    joined = re.sub(r"(>=|<=|!=|=|>|<|\^|~)\s+", r"\1", spec)
    return [part for part in re.split(r"[,\s]+", joined) if part]


def _npm_comparator(version: str, comparator: str) -> bool:
    comparator = comparator.strip()
    if comparator in {"", "*", "x", "X"}:
        return True
    if comparator.startswith("^"):
        return _npm_caret(version, comparator[1:])
    if comparator.startswith("~"):
        return _npm_tilde(version, comparator[1:])
    for op in _NPM_OPS:
        if comparator.startswith(op):
            target = comparator[len(op):].strip().lstrip("vV")
            return _apply_op(version, op, target)
    return _xrange_or_exact(version, comparator)


def _apply_op(version: str, op: str, target: str) -> bool:
    comparison = _compare(version, target)
    if op == ">=":
        return comparison >= 0
    if op == "<=":
        return comparison <= 0
    if op == ">":
        return comparison > 0
    if op == "<":
        return comparison < 0
    if op == "!=":
        return comparison != 0
    return comparison == 0  # "="


def _release_or_zero(text: str) -> list[int]:
    parsed = _release_and_suffix(text)
    return parsed[1] if parsed else [0]


def _npm_caret(version: str, base: str) -> bool:
    nums = _release_or_zero(base)
    nums = (nums + [0, 0, 0])[:3]
    major, minor, patch = nums
    if major > 0:
        upper = [major + 1, 0, 0]
    elif minor > 0:
        upper = [0, minor + 1, 0]
    else:
        upper = [0, 0, patch + 1]
    return _cmp_tuple(version, nums) >= 0 and _cmp_tuple(version, upper) < 0


def _npm_tilde(version: str, base: str) -> bool:
    parsed = _release_and_suffix(base)
    components = parsed[1] if parsed else [0]
    nums = (components + [0, 0, 0])[:3]
    if len(components) >= 2:
        upper = [nums[0], nums[1] + 1, 0]
    else:
        upper = [nums[0] + 1, 0, 0]
    return _cmp_tuple(version, nums) >= 0 and _cmp_tuple(version, upper) < 0


def _xrange_or_exact(version: str, comparator: str) -> bool:
    cleaned = comparator.lstrip("vV=")
    parts = cleaned.split(".")
    nums: list[int] = []
    wildcard_index: int | None = None
    for index, part in enumerate(parts):
        if part in {"x", "X", "*", ""}:
            wildcard_index = index
            break
        if not part.isdigit():
            return _compare(version, cleaned) == 0  # prerelease / unusual token → exact
        nums.append(int(part))
    if wildcard_index is None and len(parts) >= 3:
        return _compare(version, cleaned) == 0
    if wildcard_index is None:
        wildcard_index = len(parts)
    if wildcard_index == 0:
        return True
    lower = (nums + [0, 0, 0])[:3]
    if wildcard_index == 1:
        upper = [nums[0] + 1, 0, 0]
    elif wildcard_index == 2:
        upper = [nums[0], nums[1] + 1, 0]
    else:
        upper = [nums[0] + 1, 0, 0]
    return _cmp_tuple(version, lower) >= 0 and _cmp_tuple(version, upper) < 0


# --- PyPI PEP 440 -----------------------------------------------------------------


def _pypi_satisfies(version: str, spec: str) -> bool:
    clauses = [clause.strip() for clause in spec.split(",") if clause.strip()]
    return all(_pep440_clause(version, clause) for clause in clauses)


def _pep440_clause(version: str, clause: str) -> bool:
    for op in _PEP440_OPS:
        if clause.startswith(op):
            return _pep440_op(version, op, clause[len(op):].strip())
    return _compare(version, clause) == 0


def _pep440_op(version: str, op: str, target: str) -> bool:
    if op == "===":
        return version.strip() == target
    if op == "==":
        return _pep440_eq(version, target)
    if op == "!=":
        return not _pep440_eq(version, target)
    if op == "~=":
        components = _release_or_zero(target)
        if len(components) < 2:
            return False
        upper = components[:-1]
        upper[-1] += 1
        return _compare(version, target) >= 0 and _cmp_tuple(version, upper) < 0
    comparison = _compare(version, target)
    if op == ">=":
        return comparison >= 0
    if op == "<=":
        return comparison <= 0
    if op == ">":
        return comparison > 0
    if op == "<":
        return comparison < 0
    return False


def _pep440_eq(version: str, target: str) -> bool:
    if target.endswith(".*"):
        prefix = _release_or_zero(target[:-2])
        candidate = _release_or_zero(version)
        return candidate[: len(prefix)] == prefix
    return _compare(version, target) == 0
