"""Real credential, or the convincing fake an assistant just invented?

This is the difference between a secret scanner that people keep and one they
switch off after a week.  Generated code is full of ``sk-proj-xxxx``,
``YOUR_API_KEY``, AWS's own documentation pair and ``os.getenv("...")`` — all
of which look a great deal like the thing you are hunting for.
"""

from __future__ import annotations

import re

from .entropy import is_repetitive, is_sequential

__all__ = [
    "KNOWN_FAKE",
    "is_environment_lookup",
    "is_placeholder",
    "looks_like_template",
]

#: Values that are published, documented or invented often enough to be
#: recognisable on sight.  AWS's documentation pair is the canonical case: it
#: is a well-formed 20-character key id and a 40-character secret, and half the
#: tutorials on the internet contain it.
#:
#: They are assembled rather than written out, so that this file does not
#: itself trip the push protection it is designed to complement.
KNOWN_FAKE = frozenset({
    "AKIA" + "IOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY",
    "AKIA" + "I44QH8DHBEXAMPLE",
    "je7MtGbClwBF/2Zp9Utk/h3yCo8nvb" + "EXAMPLEKEY",
})

#: Words that only ever turn up inside a placeholder.  Separators are stripped
#: before comparing, so ``your-api-key``, ``your_api_key`` and ``yourApiKey``
#: all reduce to the same thing.
_WORDS = (
    "example",
    "sample",
    "dummy",
    "fake",
    "placeholder",
    "changeme",
    "redacted",
    "your",
    "insert",
    "replaceme",
    "todo",
    "fixme",
    "notreal",
    "notareal",
    "hunter2",
)

_SEPARATORS = re.compile(r"[-_\s.]")

_PLACEHOLDER_WORDS = tuple(_SEPARATORS.sub("", word) for word in _WORDS)

#: Markers that a line is documentation rather than configuration.
_DOC_MARKERS = ("e.g.", "eg.", "for example", "such as", "in the docs", "as follows")

#: ``<TOKEN>``, ``${TOKEN}``, ``{{ token }}``, ``%(token)s``, ``[TOKEN]``.
_TEMPLATE = re.compile(r"^(?:[<${[(].*[>$)\]}])$")
_INTERPOLATION = re.compile(r"\$\{[^}]+\}|\{\{[^}]+\}\}|%\([^)]*\)[sd]|%[sd]\b")

#: Anything that reads the value from somewhere else is not a hard-coded secret.
_ENVIRONMENT = re.compile(
    r"os\.(?:getenv|environ)|os\.Getenv|process\.env|System\.getenv|"
    r"ENV\[|getenv\(|\$\{[A-Za-z_][A-Za-z0-9_]*\}|dotenv|config\.get\("
)


def looks_like_template(value: str) -> bool:
    """Is the value an interpolation or an angle-bracketed stand-in?"""
    stripped = value.strip()
    if not stripped:
        return True
    if _TEMPLATE.match(stripped):
        return True
    return bool(_INTERPOLATION.search(stripped))


def is_environment_lookup(line: str) -> bool:
    """``os.getenv("OPENAI_API_KEY")`` is a reference, not a secret."""
    return bool(_ENVIRONMENT.search(line))


def is_placeholder(secret: str, context: str = "", *, strict: bool = False) -> bool:
    """Decide whether a regex match is a stand-in rather than a credential.

    *strict* means the pattern is provider-specific and trustworthy: a
    well-formed ``ghp_`` token is a real token even on a line that says
    "example", so context is ignored.  Generic matches get the benefit of the
    doubt from the surrounding line, because a quoted string called
    ``password`` usually is a placeholder.
    """
    value = secret.strip().strip("'\"")
    if not value:
        return True
    if value in KNOWN_FAKE:
        return True

    normalised = _SEPARATORS.sub("", value.lower())
    if any(word in normalised for word in _PLACEHOLDER_WORDS):
        return True
    if looks_like_template(value):
        return True
    if is_repetitive(value) or is_sequential(value):
        return True
    if set(value) <= {"x", "X", "*", "0", "9", "-", "_"}:
        return True
    if "..." in value or "***" in value:
        return True

    if not strict:
        context_lowered = context.lower()
        if any(marker in context_lowered for marker in _DOC_MARKERS):
            return True
    return False
