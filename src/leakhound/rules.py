"""The detectors.

Two kinds, and the difference matters:

* **high** confidence — the pattern is the provider's own format (``ghp_`` +
  36 characters).  If it matches, it is a token, whatever the surrounding
  line claims.
* **generic** — "something called ``api_key`` assigned a string".  These need
  entropy and context to stay quiet, or the scanner cries wolf on every
  ``password = "your-password"`` in a README.
"""

from __future__ import annotations

import re

from .models import Rule

__all__ = ["RULES", "RULES_BY_ID", "rule"]


def rule(
    rule_id: str,
    description: str,
    pattern: str,
    *,
    secret_group: int | None = None,
    min_entropy: float = 0.0,
    min_length: int = 0,
    confidence: str = "high",
    tags: tuple[str, ...] = (),
) -> Rule:
    """Build a rule, inferring the secret's group when the pattern has one.

    Without this, a pattern written without parentheses silently asks for
    group 1 and blows up at match time -- which is exactly what happened the
    first time these rules were run.
    """
    compiled = re.compile(pattern)
    if secret_group is None:
        secret_group = 1 if compiled.groups else 0
    return Rule(
        id=rule_id,
        description=description,
        pattern=compiled,
        secret_group=secret_group,
        min_entropy=min_entropy,
        min_length=min_length,
        tags=tags + (confidence,),
    )


RULES: tuple[Rule, ...] = (
    rule(
        "aws-access-key-id",
        "AWS access key id",
        r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b",
        secret_group=0,
        tags=("cloud",),
    ),
    rule(
        "aws-secret-access-key",
        "AWS secret access key",
        r"""(?i)\baws_?secret_?access_?key\b\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""",
        min_entropy=3.0,
        tags=("cloud",),
    ),
    rule(
        "github-token",
        "GitHub token",
        r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
        tags=("scm",),
    ),
    rule(
        "github-fine-grained-token",
        "GitHub fine-grained personal access token",
        r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b",
        tags=("scm",),
    ),
    rule(
        "openai-key",
        "OpenAI API key",
        r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,120}\b",
        min_entropy=3.0,
        tags=("model",),
    ),
    rule(
        "anthropic-key",
        "Anthropic API key",
        r"\bsk-ant-[A-Za-z0-9_-]{20,120}\b",
        min_entropy=3.0,
        tags=("model",),
    ),
    rule(
        "stripe-key",
        "Stripe live key",
        r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,120}\b",
        tags=("payments",),
    ),
    rule(
        "google-api-key",
        "Google API key",
        r"\bAIza[0-9A-Za-z_-]{35}\b",
        tags=("cloud",),
    ),
    rule(
        "google-oauth-client-secret",
        "Google OAuth client secret",
        r"\bGOCSPX-[0-9A-Za-z_-]{20,60}\b",
        tags=("cloud",),
    ),
    rule(
        "slack-token",
        "Slack token",
        r"\bxox[baprs]-[0-9A-Za-z-]{10,120}\b",
        tags=("chat",),
    ),
    rule(
        "slack-webhook",
        "Slack incoming webhook",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{12,}",
        secret_group=0,
        tags=("chat",),
    ),
    rule(
        "private-key",
        "Private key block",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        secret_group=0,
        tags=("crypto",),
    ),
    rule(
        "jwt",
        "JSON Web Token",
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        secret_group=0,
        min_entropy=3.0,
        tags=("token",),
    ),
    rule(
        "database-url",
        "Database connection string with a password",
        r"""(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:(?!\$\{)([^\s@/]+)@""",
        min_entropy=2.0,
        confidence="generic",
        tags=("database",),
    ),
    rule(
        "url-basic-auth",
        "Password embedded in a URL",
        r"""[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/@:'"]+:(?!\$\{)([^\s/@'"]+)@""",
        min_entropy=2.0,
        confidence="generic",
        tags=("url",),
    ),
    rule(
        "azure-storage-key",
        "Azure storage account key",
        r"(?i)\bAccountKey\s*=\s*([A-Za-z0-9+/=]{40,100})",
        min_entropy=3.5,
        tags=("cloud",),
    ),
    rule(
        "sendgrid-key",
        "SendGrid API key",
        r"\bSG\.[A-Za-z0-9_-]{20,24}\.[A-Za-z0-9_-]{40,50}\b",
        tags=("email",),
    ),
    rule(
        "twilio-key",
        "Twilio API key",
        r"\bSK[0-9a-f]{32}\b",
        min_entropy=3.0,
        tags=("comms",),
    ),
    rule(
        "discord-bot-token",
        "Discord bot token",
        r"\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b",
        tags=("chat",),
    ),
    rule(
        "npm-token",
        "npm access token",
        r"\bnpm_[A-Za-z0-9]{36}\b",
        tags=("package",),
    ),
    rule(
        "huggingface-token",
        "Hugging Face token",
        r"\bhf_[A-Za-z0-9]{30,60}\b",
        tags=("model",),
    ),
    rule(
        "generic-secret-assignment",
        "Secret-looking value assigned to a secret-looking name",
        r"""(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|"""
        r"""client[_-]?secret|private[_-]?key|password|passwd|pwd)\b\s*[:=]\s*"""
        r"""(['"])([^'"\n]{8,120})\1""",
        secret_group=2,
        min_entropy=3.2,
        min_length=8,
        confidence="generic",
        tags=("generic",),
    ),
    rule(
        "generic-secret-bare",
        "Unquoted secret-looking assignment",
        r"""(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|"""
        r"""client[_-]?secret)\b\s*[:=]\s*([A-Za-z0-9_\-.]{16,120})""",
        min_entropy=3.5,
        min_length=16,
        confidence="generic",
        tags=("generic",),
    ),
)

RULES_BY_ID = {item.id: item for item in RULES}
