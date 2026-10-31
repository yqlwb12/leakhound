"""leakhound -- find credentials in AI-written source, without crying wolf.

    >>> from leakhound import scan_text
    >>> findings = scan_text('token = "ghp_' + "a" * 36 + '"', "config.py")
    >>> [finding.rule_id for finding in findings]
    ['github-token']

The interesting part is not the regexes, it is the four gates between a match
and a report: placeholder detection, entropy, environment lookups, and
masking.
"""

from .models import Finding, Rule, fingerprint, mask
from .report import render
from .rules import RULES
from .scanner import ScanResult, scan, scan_text

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "RULES",
    "Rule",
    "ScanResult",
    "__version__",
    "fingerprint",
    "mask",
    "render",
    "scan",
    "scan_text",
]
