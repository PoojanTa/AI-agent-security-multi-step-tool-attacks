"""Structured logging + end-of-run statistics.

Design decision
---------------
The baseline is a black box: you cannot tell *why* it found (or missed) an attack.
Every improvement in this project is justified by a measurement, so observability
is a V1 requirement, not an afterthought. ``RunLogger`` records one
``InteractionRecord`` per ``env.interact`` and aggregates counters as it goes, so
the final ``summary()`` is O(1) rather than a re-scan of history.

What each interaction records (per the roadmap):
    prompt, execution time, tool calls, predicates, candidate-generated, breach.

End-of-run statistics:
    interactions, successful attacks (breaches), avg interaction time,
    tool frequency, predicate frequency, candidates returned, unique cells.

Time complexity: O(1) amortised per interaction; summary is O(#distinct tools +
#distinct predicates).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any


@dataclass
class InteractionRecord:
    """Immutable-ish snapshot of a single agent interaction turn."""

    step: int
    prompt: str
    duration_ms: float
    tool_names: tuple[str, ...]
    predicate_names: tuple[str, ...]
    breach: bool
    candidate_emitted: bool


@dataclass
class RunLogger:
    """Accumulates interaction records and derived statistics for one run."""

    verbose: bool = True
    records: list[InteractionRecord] = field(default_factory=list)
    tool_freq: Counter[str] = field(default_factory=Counter)
    predicate_freq: Counter[str] = field(default_factory=Counter)
    _total_duration_ms: float = 0.0
    _breaches: int = 0
    _candidates: int = 0

    # ------------------------------------------------------------------ record
    def record_interaction(
        self,
        *,
        step: int,
        prompt: str,
        duration_ms: float,
        tool_names: tuple[str, ...],
        predicate_names: tuple[str, ...],
        breach: bool,
        candidate_emitted: bool,
    ) -> None:
        self.records.append(
            InteractionRecord(
                step=step,
                prompt=prompt,
                duration_ms=duration_ms,
                tool_names=tool_names,
                predicate_names=predicate_names,
                breach=breach,
                candidate_emitted=candidate_emitted,
            )
        )
        self._total_duration_ms += duration_ms
        self.tool_freq.update(tool_names)
        self.predicate_freq.update(predicate_names)
        self._breaches += int(breach)
        self._candidates += int(candidate_emitted)

    # ---------------------------------------------------------------- summary
    def summary(self, *, candidates_returned: int, unique_cells: int) -> dict[str, Any]:
        n = len(self.records)
        avg_ms = (self._total_duration_ms / n) if n else 0.0
        return {
            "interactions": n,
            "successful_attacks": self._breaches,
            "avg_interaction_ms": round(avg_ms, 2),
            "candidates_emitted": self._candidates,
            "candidates_returned": candidates_returned,
            "unique_cells": unique_cells,
            "tool_frequency": dict(self.tool_freq.most_common()),
            "predicate_frequency": dict(self.predicate_freq.most_common()),
        }

    def print_summary(self, *, candidates_returned: int, unique_cells: int) -> dict[str, Any]:
        stats = self.summary(
            candidates_returned=candidates_returned, unique_cells=unique_cells
        )
        if not self.verbose:
            return stats
        line = "-" * 52
        print(f"\n{line}\n ATTACK RUN STATISTICS\n{line}")
        print(f"  Interactions           : {stats['interactions']}")
        print(f"  Successful attacks     : {stats['successful_attacks']}")
        print(f"  Avg interaction time   : {stats['avg_interaction_ms']} ms")
        print(f"  Candidates emitted     : {stats['candidates_emitted']}")
        print(f"  Candidates returned    : {stats['candidates_returned']}")
        print(f"  Unique scoring cells   : {stats['unique_cells']}")
        print(f"  Tool frequency         : {stats['tool_frequency'] or '{}'}")
        print(f"  Predicate frequency    : {stats['predicate_frequency'] or '{}'}")
        print(f"{line}")
        return stats
