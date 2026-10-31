"""The few data structures everything else agrees on."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

__all__ = ["Rule", "Finding", "mask", "fingerprint"]


def mask(secret: str) -> str:
    """Show just enough of a secret to recognise it, never enough to use it.

    Every report, log line and JSON field goes through this.  A scanner that
    prints what it finds turns one leak into two.
    """
    if not secret:
        return ""
    if len(secret) <= 8:
        return secret[0] + "*" * (len(secret) - 1)
    return secret[:4] + "*" * min(16, len(secret) - 8) + secret[-4:]


def fingerprint(rule_id: str, secret: str) -> str:
    """Stable, non-reversible id for a finding, so baselines can suppress it
    without storing the secret itself."""
    digest = hashlib.sha256(("%s:%s" % (rule_id, secret)).encode("utf-8"))
    return digest.hexdigest()[:16]


@dataclass(frozen=True)
class Rule:
    """One detector: a regex, plus the gates that decide if a match is real."""

    id: str
    description: str
    pattern: re.Pattern
    secret_group: int = 1
    min_entropy: float = 0.0
    min_length: int = 0
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.secret_group < 0:
            raise ValueError("secret_group must be >= 0")
        if self.pattern.groups < self.secret_group:
            raise ValueError(
                "rule %r has no capture group %d" % (self.id, self.secret_group)
            )
        if not 0.0 <= self.min_entropy <= 8.0:
            raise ValueError("min_entropy must be between 0 and 8")


@dataclass
class Finding:
    """A secret that survived every gate."""

    rule_id: str
    description: str
    path: str
    line: int
    column: int
    secret: str
    entropy: float
    fingerprint: str
    snippet: str

    @property
    def masked(self) -> str:
        return mask(self.secret)

    def as_dict(self) -> dict:
        return {
            "rule": self.rule_id,
            "description": self.description,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "secret": self.masked,
            "entropy": round(self.entropy, 3),
            "fingerprint": self.fingerprint,
            "snippet": self.snippet,
        }
