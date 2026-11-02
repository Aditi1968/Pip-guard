"""Blocking and warning rules from ``rules.yaml`` (PRD FR-5.1, FR-5.4).

The condition language is deliberately tiny (compare a feature to a number, nest with
``all``/``any``) and is interpreted, never ``eval``-ed. Reasons are fixed templates whose
placeholders are filled only with :func:`safe_text`-escaped values, because paths, IPs and
argv come straight from untrusted packages and end up in a Markdown job summary.
"""

from __future__ import annotations

import ipaddress
import operator
import string
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from pipguard.errors import PipGuardError
from pipguard.features import FEATURE_NAMES, _suspicious_argv, vectorize
from pipguard.models import BehaviorTrace, ConnectAttempt, StaticFeatures

DEFAULT_RULES_PATH = Path(__file__).with_name("rules.yaml")

# Rule-only derived features, computed here because the model's vector does not need them.
EXTRA_FEATURE_NAMES = ["connect_install_external_count"]

# Evidence strings a reason template may name, besides any feature value.
EVIDENCE_KEYS = [
    "name",
    "first_connect_install",
    "first_connect_install_external",
    "first_connect_import",
    "first_credential",
    "first_subprocess",
    "first_suspicious_subprocess",
    "first_write",
    "first_ip",
    "first_shortener",
    "typosquat_target",
]

SAFE_TEXT_LIMIT = 120

# HTML entities rather than backslash escapes: they survive every Markdown renderer and
# leave no raw table/code/HTML/link/mention metacharacter behind. `&` goes first.
_ESCAPES = {
    "&": "&amp;",
    "|": "&#124;",
    "`": "&#96;",
    "<": "&lt;",
    ">": "&gt;",
    "[": "&#91;",
    "]": "&#93;",
    "@": "&#64;",
    "\\": "&#92;",
}


def safe_text(value: object, limit: int = SAFE_TEXT_LIMIT) -> str:
    """Untrusted value -> one short line that cannot break a Markdown table or inject markup.

    Control/format characters (newlines, bidi overrides, zero-width) become spaces, the text
    is capped at ``limit`` characters (plus an ellipsis), then Markdown/HTML metacharacters
    are replaced by entities.
    """
    text = "".join(
        " " if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") else ch for ch in str(value)
    )
    if len(text) > limit:
        text = text[:limit] + "…"
    return "".join(_ESCAPES.get(ch, ch) for ch in text)


# ---------------------------------------------------------------- schema


class _Strict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)


Op = Literal[">=", ">", "==", "<=", "<"]
_OPS: dict[str, Callable[[float, float], bool]] = {
    ">=": operator.ge,
    ">": operator.gt,
    "==": operator.eq,
    "<=": operator.le,
    "<": operator.lt,
}


class Leaf(_Strict):
    feature: str
    op: Op
    value: float


class AllOf(_Strict):
    all_: list[Condition] = Field(alias="all", min_length=1)


class AnyOf(_Strict):
    any_: list[Condition] = Field(alias="any", min_length=1)


Condition = Leaf | AllOf | AnyOf
AllOf.model_rebuild()
AnyOf.model_rebuild()


class Rule(_Strict):
    id: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")
    description: str
    reason: str = Field(min_length=1)
    when: Condition


class RuleSet(_Strict):
    blocking: list[Rule] = Field(default_factory=list)
    warning: list[Rule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check(self) -> RuleSet:
        ids = [r.id for r in self.blocking + self.warning]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate rule id")
        for rule in self.blocking + self.warning:
            for name in _features_in(rule.when):
                if name not in _KNOWN_FEATURES:
                    raise ValueError(f"rule {rule.id}: unknown feature {name!r}")
            _check_template(rule)
        return self


_KNOWN_FEATURES = frozenset(FEATURE_NAMES + EXTRA_FEATURE_NAMES)
_PLACEHOLDERS = _KNOWN_FEATURES | frozenset(EVIDENCE_KEYS)


def _features_in(cond: Condition) -> list[str]:
    if isinstance(cond, Leaf):
        return [cond.feature]
    children = cond.all_ if isinstance(cond, AllOf) else cond.any_
    return [name for c in children for name in _features_in(c)]


def _check_template(rule: Rule) -> None:
    try:
        parts = list(string.Formatter().parse(rule.reason))
    except ValueError as exc:
        raise ValueError(f"rule {rule.id}: bad reason template: {exc}") from exc
    for _literal, field, spec, conversion in parts:
        if field is None:
            continue
        # Plain names only: no attribute access, indexing, conversions or format specs.
        if field not in _PLACEHOLDERS or spec or conversion:
            raise ValueError(f"rule {rule.id}: bad placeholder {{{field}}}")


class RuleHit(_Strict):
    rule_id: str
    klass: Literal["blocking", "warning"]
    reason: str


def load_rules(path: Path | None = None) -> RuleSet:
    """Load and validate ``rules.yaml``. Missing or malformed rules are a hard error."""
    path = path or DEFAULT_RULES_PATH
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        ruleset = RuleSet.model_validate(data)
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise PipGuardError(f"invalid rules file {path}: {exc}") from exc
    if not ruleset.blocking and not ruleset.warning:
        raise PipGuardError(f"rules file {path} has no rules")
    return ruleset


# ---------------------------------------------------------------- evaluation


def _holds(cond: Condition, features: dict[str, float]) -> bool:
    if isinstance(cond, Leaf):
        # A feature the caller did not supply is a bug; raise rather than silently pass.
        return _OPS[cond.op](features[cond.feature], cond.value)
    if isinstance(cond, AllOf):
        return all(_holds(c, features) for c in cond.all_)
    return any(_holds(c, features) for c in cond.any_)


def _fmt_number(v: float) -> str:
    return str(int(v)) if float(v).is_integer() else f"{v:.2f}"


def render(template: str, features: dict[str, float], evidence: dict[str, str]) -> str:
    """Fill a validated template; every value goes through :func:`safe_text`."""
    values = {k: safe_text(_fmt_number(v)) for k, v in features.items()}
    values |= {k: safe_text(evidence.get(k) or "unknown") for k in EVIDENCE_KEYS}
    return template.format_map(values)


def evaluate(
    ruleset: RuleSet, features: dict[str, float], evidence: dict[str, str]
) -> list[RuleHit]:
    """All rules that fire, blocking first, in file order."""
    hits: list[RuleHit] = []
    for klass, rules in (("blocking", ruleset.blocking), ("warning", ruleset.warning)):
        for rule in rules:
            try:
                fired = _holds(rule.when, features)
            except KeyError as exc:
                raise PipGuardError(f"rule {rule.id}: feature {exc} not supplied") from exc
            if fired:
                reason = render(rule.reason, features, evidence)
                hits.append(RuleHit(rule_id=rule.id, klass=klass, reason=reason))  # type: ignore[arg-type]
    return hits


# ---------------------------------------------------------------- inputs


def _is_external(c: ConnectAttempt) -> bool:
    """An IP connect that leaves the host. Unparseable inet addresses count as external."""
    if c.family not in ("AF_INET", "AF_INET6"):
        return False
    try:
        ip = ipaddress.ip_address(c.address)
    except ValueError:
        return True
    return not (ip.is_loopback or ip.is_unspecified)


def _endpoint(c: ConnectAttempt) -> str:
    host = f"[{c.address}]" if c.family == "AF_INET6" else c.address
    return host if c.port is None else f"{host}:{c.port}"


def build_inputs(
    static: StaticFeatures, trace: BehaviorTrace | None = None
) -> tuple[dict[str, float], dict[str, str]]:
    """Feature dict (``vectorize`` + rule-only extras) and raw evidence strings for templates.

    Evidence is left unescaped here; :func:`render` escapes it, so no caller can forget.
    """
    features = vectorize(static, trace)
    connects = trace.connects if trace else []
    install = [c for c in connects if c.step == "install"]
    external = [c for c in install if _is_external(c)]
    features["connect_install_external_count"] = float(len(external))

    def first(items: list[str]) -> str:
        return items[0] if items else ""

    arts = static.artifacts
    subs = trace.subprocesses if trace else []
    evidence = {
        "name": static.spec.name,
        "first_connect_install": first([_endpoint(c) for c in install]),
        "first_connect_install_external": first([_endpoint(c) for c in external]),
        "first_connect_import": first([_endpoint(c) for c in connects if c.step == "import"]),
        "first_credential": first([r.path for r in trace.credential_reads] if trace else []),
        "first_subprocess": first([" ".join(s.argv) for s in subs]),
        "first_suspicious_subprocess": first(
            [" ".join(s.argv) for s in subs if _suspicious_argv(s.argv)]
        ),
        "first_write": first([w.path for w in trace.writes_outside_allowed] if trace else []),
        "first_ip": first([ip for a in arts for ip in a.ip_literals]),
        "first_shortener": first([u for a in arts for u in a.shortener_urls]),
        "typosquat_target": static.typosquat.target or "",
    }
    return features, evidence
