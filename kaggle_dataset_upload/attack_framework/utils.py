"""Small, dependency-light helpers shared across the framework.

Design decision
---------------
Anything that is (a) trivial, (b) reused by >=2 modules, and (c) has no framework
dependencies lives here. Keeping it thin avoids a "utils junk drawer": if a helper
starts to carry domain logic (trace parsing, scoring) it belongs in its own module
(``trace_analyzer``, ``evaluator``), not here.

We re-export the SDK ``Timebox`` so the rest of the framework depends on *our*
timing abstraction rather than reaching into ``aicomp_sdk.utils`` directly -- if
the SDK ever moves it, we change one line.
"""

from __future__ import annotations

import time
from collections.abc import Sequence

from aicomp_sdk.utils.timebox import Timebox  # re-exported on purpose

__all__ = ["Timebox", "messages_signature", "monotonic_ms", "truncate"]


def messages_signature(user_messages: Sequence[str]) -> tuple[str, ...]:
    """V1 candidate signature: the exact user-message chain.

    Matches the roadmap's initial dedup key ("signature = tuple(messages)"). It is
    cheap and never collapses two *different* prompt chains, but it also does not
    recognise that two different chains can drive the *same* scored tool-trace --
    that scoring-aligned key arrives in V2 via ``evaluator.score_cell_hash``.
    """
    return tuple(user_messages)


def monotonic_ms() -> float:
    """Monotonic clock in milliseconds (immune to wall-clock adjustments)."""
    return time.perf_counter() * 1000.0


def truncate(text: str, limit: int = 80) -> str:
    """One-line, length-bounded preview of a possibly-multiline string."""
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."
