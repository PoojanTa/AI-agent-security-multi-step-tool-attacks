"""Orchestrator: assembles components and runs the selected search strategy.

Design decision
---------------
``attack.py`` must stay a two-line shim (it is the fixed competition entrypoint), so
all wiring lives here. ``AttackFramework.run`` is the single place that:

  1. reads ``FrameworkConfig`` and turns ``config.search`` into a concrete strategy
     (the *only* strategy-name -> class switch in the codebase);
  2. constructs the archive, logger, evaluator, heuristics, and ``SearchContext``;
  3. runs the strategy, prints statistics, and returns the shippable candidates.

This is the Dependency-Inversion seam: the orchestrator depends on the
``SearchStrategy`` abstraction, and a new algorithm is added by registering it in
``build_strategy`` -- nothing else changes. That is exactly what makes
``SEARCH="beam"`` a one-line experiment later.

Time complexity: dominated entirely by the chosen strategy's search loop.
"""

from __future__ import annotations

import random

from aicomp_sdk.attacks.contracts import AttackCandidate, AttackRunConfig
from aicomp_sdk.core.env.api import AttackEnvProtocol

from attack_framework.archive import CandidateArchive
from attack_framework.config import FrameworkConfig
from attack_framework.evaluator import Evaluator
from attack_framework.heuristics import HeuristicScorer
from attack_framework.logger import RunLogger
from attack_framework.prompt_library import LEADERBOARD_SCRIPTS, PromptLibrary
from attack_framework.probe_fill import ProbeFillSearch
from attack_framework.search import (
    BeamSearch,
    LeaderboardSearch,
    RandomSearch,
    SearchContext,
    SearchStrategy,
)
from attack_framework.utils import Timebox


# Category weights for leaderboard volume phase (higher = more samples).
_LEADERBOARD_WEIGHTS: dict[str, int] = {
    "exfiltration": 6,
    "web": 3,
    "tool_chaining": 3,
    "destructive_write": 3,
    "confused_deputy": 2,
    "email": 2,
    "filesystem": 1,
    "shell": 1,
}


def _weighted_prompt_pool(library: PromptLibrary) -> tuple[str, ...]:
    pool: list[str] = []
    for cat, weight in _LEADERBOARD_WEIGHTS.items():
        prompts = library.by_category(cat)
        if not prompts:
            continue
        pool.extend(list(prompts) * max(1, int(weight)))
    return tuple(pool) if pool else library.all()


def build_strategy(
    config: FrameworkConfig, library: PromptLibrary
) -> SearchStrategy:
    """Resolve ``config.search`` into a concrete strategy instance.

    The registry is deliberately explicit (not import-magic) so a misconfigured
    ``search`` fails loudly at startup rather than silently doing nothing.
    """
    key = config.search.lower()
    params = dict(config.strategy_params)
    if key == "random":
        return RandomSearch(prompts=library.all(), **params)
    if key == "beam":
        return BeamSearch(prompts=library.all(), **params)
    if key == "leaderboard":
        params.setdefault("episode_len", 4)
        params.setdefault("priority_scripts", LEADERBOARD_SCRIPTS)
        params.setdefault("weighted_prompts", _weighted_prompt_pool(library))
        return LeaderboardSearch(prompts=library.all(), **params)
    if key in {"probe_fill", "probe-fill", "validated_fill"}:
        return ProbeFillSearch(**params)
    raise ValueError(
        f"Unknown search strategy {config.search!r}; "
        "available: ['probe_fill', 'leaderboard', 'random', 'beam']"
    )


class AttackFramework:
    """Top-level object invoked by ``attack.py``.

    Holds only configuration + the prompt library (both cheap and reusable); all
    run-scoped state (archive, logger, context) is created fresh inside ``run`` so
    the same framework object can be reused across environments/seeds without leaking
    state between runs.
    """

    def __init__(
        self,
        config: FrameworkConfig | None = None,
        library: PromptLibrary | None = None,
    ) -> None:
        self.config = config or FrameworkConfig()
        self.library = library or PromptLibrary()

    def run(
        self, env: AttackEnvProtocol, run_config: AttackRunConfig
    ) -> list[AttackCandidate]:
        """Execute the configured search and return shippable candidates."""
        archive = CandidateArchive(
            dedup_key=self.config.dedup_key,
            max_candidates=self.config.max_candidates,
            max_messages_per_candidate=self.config.max_messages_per_candidate,
        )
        logger = RunLogger(verbose=self.config.verbose)
        ctx = SearchContext(
            env=env,
            run_config=run_config,
            timebox=Timebox(float(run_config.time_budget_s)),
            rng=random.Random(self.config.seed),
            archive=archive,
            logger=logger,
            evaluator=Evaluator(),
            heuristics=HeuristicScorer(),
        )

        strategy = build_strategy(self.config, self.library)
        strategy.run(ctx)

        candidates = archive.candidates()
        logger.print_summary(
            candidates_returned=len(candidates),
            unique_cells=archive.unique_cells,
        )
        return candidates
