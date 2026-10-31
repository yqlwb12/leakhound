"""Four ways to say "you committed a key"."""

from __future__ import annotations

import json

from .models import Finding
from .scanner import ScanResult

__all__ = ["to_text", "to_json", "to_sarif", "to_markdown", "render", "FORMATS"]

FORMATS = ("text", "json", "sarif", "markdown")

_RESET = "\x1b[0m"
_RED = "\x1b[38;2;235;105;105m"
_YELLOW = "\x1b[38;2;224;175;104m"
_DIM = "\x1b[38;2;120;126;148m"
_BOLD = "\x1b[1m"


def _paint(text: str, colour: str, enabled: bool) -> str:
    return text if not enabled else colour + text + _RESET


def to_text(result: ScanResult, *, colour: bool = False) -> str:
    if result.clean:
        return _paint(
            "no secrets found in %d file%s" % (
                result.files_scanned,
                "" if result.files_scanned == 1 else "s",
            ),
            _DIM,
            colour,
        )

    lines = []
    current_path = None
    for finding in result.findings:
        if finding.path != current_path:
            current_path = finding.path
            lines.append("")
            lines.append(_paint(current_path, _BOLD, colour))
        location = "%4d:%-3d" % (finding.line, finding.column)
        label = "%-28s" % finding.rule_id
        lines.append(
            "  %s  %s  %-30s %s"
            % (
                _paint(location, _YELLOW, colour),
                _paint(label, _RED, colour),
                finding.masked,
                _paint("%.1f bits" % finding.entropy, _DIM, colour),
            )
        )
        lines.append("        %s" % _paint(finding.snippet, _DIM, colour))

    lines.append("")
    lines.append(
        "%d finding%s in %d file%s"
        % (
            result.count,
            "" if result.count == 1 else "s",
            result.files_scanned,
            "" if result.files_scanned == 1 else "s",
        )
    )
    return "\n".join(lines).lstrip("\n")


def _payload(result: ScanResult) -> dict:
    return {
        "tool": "leakhound",
        "version": _version(),
        "files_scanned": result.files_scanned,
        "skipped": [{"path": path, "reason": reason} for path, reason in result.skipped],
        "summary": {"findings": result.count},
        "findings": [finding.as_dict() for finding in result.findings],
    }


def _version() -> str:
    from . import __version__

    return __version__


def to_json(result: ScanResult) -> str:
    return json.dumps(_payload(result), indent=2, ensure_ascii=False)


def to_sarif(result: ScanResult) -> str:
    """SARIF 2.1.0, which is what GitHub code scanning ingests."""
    from .rules import RULES_BY_ID

    used = {finding.rule_id for finding in result.findings}
    driver_rules = []
    for rule_id in sorted(used):
        spec = RULES_BY_ID.get(rule_id)
        entry = {
            "id": rule_id,
            "name": rule_id.replace("-", " ").title(),
            "shortDescription": {"text": spec.description if spec else rule_id},
            "defaultConfiguration": {"level": "error"},
        }
        if spec is not None:
            entry["properties"] = {"tags": list(spec.tags)}
        driver_rules.append(entry)

    results = []
    for finding in result.findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": "error",
                "message": {
                    "text": "%s (%s...%s) at %s:%d"
                    % (
                        finding.description,
                        finding.masked[:4],
                        finding.masked[-4:],
                        finding.path,
                        finding.line,
                    )
                },
                "partialFingerprints": {"leakhoundFingerprint": finding.fingerprint},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": {
                                "startLine": finding.line,
                                "startColumn": max(1, finding.column),
                            },
                        }
                    }
                ],
            }
        )

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "leakhound",
                        "informationUri": "https://github.com/yqlwb12/leakhound",
                        "version": _version(),
                        "rules": driver_rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False)


def to_markdown(result: ScanResult) -> str:
    if result.clean:
        return "**leakhound:** no secrets found in %d files." % result.files_scanned
    lines = [
        "**leakhound found %d potential secret%s**" % (
            result.count,
            "" if result.count == 1 else "s",
        ),
        "",
        "| File | Line | Rule | Value |",
        "| --- | --- | --- | --- |",
    ]
    for finding in result.findings:
        lines.append(
            "| `%s` | %d | `%s` | `%s` |"
            % (finding.path, finding.line, finding.rule_id, finding.masked)
        )
    lines.append("")
    lines.append("Values are masked. Rotate anything that was ever real.")
    return "\n".join(lines)


def render(result: ScanResult, *, format: str = "text", colour: bool = False) -> str:
    if format == "json":
        return to_json(result)
    if format == "sarif":
        return to_sarif(result)
    if format == "markdown":
        return to_markdown(result)
    return to_text(result, colour=colour)
