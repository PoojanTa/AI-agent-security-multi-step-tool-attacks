"""De-duplicated store of findings -- the product the framework ships.

Design decision
---------------
``run()`` must return ``list[AttackCandidate]``. The archive is what accumulates
them. Two dedup keys are supported, selected by config:

* ``"messages"`` (V1, per roadmap): signature = the exact user-message chain. Cheap,
  never merges genuinely different prompt chains.
* ``"cell"`` (V2+): signature = the scoring cell hash. This is *scoring-aligned* --
  the +2 diversity bonus is per unique cell hash, so deduping on it stops us from
  spending our 2000-candidate budget on chains that collapse to one scored cell.

We track the set of distinct **scoring** cell hashes regardless of dedup key, so the
"unique cells" statistic always reflects the real diversity term.

Why this beats the baseline
---------------------------
The baseline appends every breach with no notion of duplication or budget, so it can
emit thousands of redundant candidates and blow the replay cap on near-identical
chains. The archive enforces both caps (``max_candidates``,
``max_messages_per_candidate``) and keeps the highest-value entry per signature.

Time complexity: O(1) amortised per ``add`` (hash-set membership).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from aicomp_sdk.attacks.contracts import AttackCandidate

from attack_framework.evaluator import Finding
from attack_framework.utils import messages_signature


@dataclass
class ArchiveEntry:
    """One retained finding plus the message chain that produced it."""

    messages: tuple[str, ...]
    finding: Finding


class CandidateArchive:
    """Insertion-ordered, de-duplicated collection of findings."""

    def __init__(
        self,
        *,
        dedup_key: str = "messages",
        max_candidates: int = 2000,
        max_messages_per_candidate: int = 32,
    ) -> None:
        if dedup_key not in ("messages", "cell"):
            raise ValueError(f"unknown dedup_key: {dedup_key!r}")
        self._dedup_key = dedup_key
        self._max_candidates = max_candidates
        self._max_messages = max_messages_per_candidate
        self._entries: dict[str, ArchiveEntry] = {}
        self._cell_hashes: set[str] = set()

    # --------------------------------------------------------------- mutation
    def _signature(self, messages: Sequence[str], finding: Finding) -> str:
        if self._dedup_key == "cell":
            return finding.cell_hash
        return repr(messages_signature(messages))

    def add(self, messages: Sequence[str], finding: Finding) -> bool:
        """Insert a finding. Returns True if it was newly stored.

        Rejects over-long chains (would fail replay) and enforces the candidate
        cap. On a signature collision we keep whichever entry has the higher scorer
        value, so dedup never lowers our realized score.
        """
        msgs = tuple(messages)
        if not msgs or len(msgs) > self._max_messages:
            return False

        self._cell_hashes.add(finding.cell_hash)
        sig = self._signature(msgs, finding)

        existing = self._entries.get(sig)
        if existing is not None:
            if finding.value > existing.finding.value:
                self._entries[sig] = ArchiveEntry(messages=msgs, finding=finding)
            return False

        if len(self._entries) >= self._max_candidates:
            return False  # budget exhausted; caller may stop early

        self._entries[sig] = ArchiveEntry(messages=msgs, finding=finding)
        return True

    # ------------------------------------------------------------------ views
    @property
    def is_full(self) -> bool:
        return len(self._entries) >= self._max_candidates

    @property
    def unique_cells(self) -> int:
        """Distinct scoring cell hashes -- the +2/each diversity term."""
        return len(self._cell_hashes)

    def is_novel_cell(self, cell_hash: str) -> bool:
        """True if this scoring cell hash has not been archived yet.

        Must be queried *before* :meth:`add`, which records the hash.
        """
        return cell_hash not in self._cell_hashes

    def entries(self) -> list[ArchiveEntry]:
        return list(self._entries.values())

    def __len__(self) -> int:
        return len(self._entries)

    def candidates(self) -> list[AttackCandidate]:
        """Materialise the shippable ``AttackCandidate`` list (highest value first)."""
        ordered = sorted(
            self._entries.values(), key=lambda e: e.finding.value, reverse=True
        )
        return [
            AttackCandidate.from_messages(entry.messages)
            for entry in ordered[: self._max_candidates]
        ]
