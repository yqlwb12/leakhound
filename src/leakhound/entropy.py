"""Shannon entropy, which is how you tell a key from a sentence.

A regex can say "this looks like an API key".  Entropy is what stops it from
shouting about ``password = "hunter2"`` and ``api_key = "your-key-here"``:
real credentials are drawn from a wide alphabet, and the bits per character
show it.
"""

from __future__ import annotations

import math
from collections import Counter

__all__ = ["entropy", "classes", "is_repetitive", "is_sequential"]


def entropy(value: str) -> float:
    """Shannon entropy in bits per character.  0 for empty or uniform strings."""
    if not value:
        return 0.0
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in Counter(value).values()
    )


def classes(value: str) -> int:
    """How many of {lower, upper, digit, symbol} the value draws from."""
    return (
        sum(
            (
                any(char.islower() for char in value),
                any(char.isupper() for char in value),
                any(char.isdigit() for char in value),
                any(not char.isalnum() for char in value),
            )
        )
    )


def is_repetitive(value: str) -> bool:
    """``aaaaaa``, ``xxxxx``, ``ababab``: the shapes a placeholder takes."""
    if len(set(value)) <= 2:
        return True
    for period in (1, 2, 3):
        if len(value) % period == 0 and value == value[:period] * (len(value) // period):
            return True
    return False


def is_sequential(value: str) -> bool:
    """``12345678``, ``abcdef``, ``abcdefghijklmnop``."""
    if len(value) < 4:
        return False
    lowered = value.lower()
    ascending = "0123456789abcdefghijklmnopqrstuvwxyz"
    for index in range(len(ascending) - len(lowered) + 1):
        if ascending[index:index + len(lowered)] == lowered:
            return True
    reversed_value = lowered[::-1]
    for index in range(len(ascending) - len(reversed_value) + 1):
        if ascending[index:index + len(reversed_value)] == reversed_value:
            return True
    return False
