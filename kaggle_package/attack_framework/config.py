"""Central, declarative configuration for the attack framework.

Design decision
---------------
Configuration is *pure data* (a frozen dataclass) with **no imports from the rest
of the framework**. This is what lets an experiment switch strategy with a single
line -- ``FrameworkConfig(search="beam")`` -- without editing ``attack.py`` or any
algorithm code. The orchestrator (``algorithm.py``) is the only place that reads
these fields and turns them into behavior, so adding a knob here never risks a
circular import.

Why it improves the baseline
----------------------------
The random baseline hard-codes its prompts, its loop, and its "reset once" policy
inline. By hoisting every choice into one object we get: reproducible runs (single
``seed``), A/B-able experiments, and a stable contract for every future search
strategy to read from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class FrameworkConfig:
    """Knobs the orchestrator reads to assemble and run a search.

    Only ``search`` and ``seed`` matter for V1; the remaining fields are declared
    now so later strategies (beam/evolutionary) have a stable home and the schema
    does not churn. Strategy-specific parameters live in ``strategy_params`` so we
    never grow one flat namespace of mutually-exclusive knobs.
    """

    # --- Search selection -------------------------------------------------
    search: str = "probe_fill"
    """Key resolved by algorithm.build_strategy().
    Options: "probe_fill" (Kaggle default), "leaderboard", "random", "beam"."""

    strategy_params: dict[str, Any] = field(default_factory=dict)
    """Free-form params handed to the selected strategy (beam width, pop size...)."""

    # --- Determinism ------------------------------------------------------
    seed: int = 123
    """Seed for the framework's own RNG (prompt choice, mutation). Distinct from
    the *environment* seed, which the evaluator/gateway owns via ``env.seed``."""

    # --- Candidate shaping ------------------------------------------------
    max_messages_per_candidate: int = 32
    """Hard cap mirrored from the gateway (MAX_REPLAY_MESSAGES_PER_FINDING = 32).
    Any candidate longer than this would be rejected at replay, so we never emit
    one that big."""

    max_candidates: int = 2000
    """Hard cap mirrored from the gateway (MAX_REPLAY_FINDINGS = 2000)."""

    # --- Archive / dedup --------------------------------------------------
    dedup_key: str = "messages"
    """"messages" -> signature = tuple(user_messages) (V1, per roadmap).
    "cell" -> signature = score_cell_signature hash (scoring-aligned; V2+)."""

    # --- Observability ----------------------------------------------------
    verbose: bool = True
    """Print the end-of-run statistics block."""

    log_traces: bool = False
    """Retain full trace dicts in memory for offline analysis (costs RAM)."""
