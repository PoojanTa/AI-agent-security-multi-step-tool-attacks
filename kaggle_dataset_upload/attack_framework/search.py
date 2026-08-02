"""Search strategies and the context facade they operate through.

Design decision
---------------
Every future algorithm (beam, evolutionary, novelty, MCTS) is "just" a different
policy for *which prompt to try next and from which state*. To make them drop-in, we
put all the cross-cutting machinery -- interacting, timing, trace evaluation, dedup,
logging, snapshotting -- behind one ``SearchContext`` facade, and reduce a strategy
to a single method: ``run(ctx)``. A strategy therefore contains only its *decision
logic*, never bookkeeping. That is the Strategy pattern, and it is what lets
``config.search`` swap algorithms without touching the orchestrator or ``attack.py``.

``SearchContext.step(prompt)`` is the one primitive a strategy needs: it sends a
message, evaluates the resulting trace, archives any finding, logs the interaction,
and returns the ``Finding`` (or ``None``). Higher-value strategies also use
``snapshot``/``restore`` to branch from promising states instead of replaying from
scratch.

Time complexity (per step): O(agent+tools for one turn) + O(#tool_events) evaluation.
"""

from __future__ import annotations

import random
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass

from aicomp_sdk.attacks.contracts import AttackRunConfig
from aicomp_sdk.core.env.api import AttackEnvProtocol

from attack_framework.archive import CandidateArchive
from attack_framework.evaluator import Evaluator, Finding
from attack_framework.heuristics import HeuristicScorer
from attack_framework.logger import RunLogger
from attack_framework.trace_analyzer import TraceStats, analyze_trace
from attack_framework.utils import Timebox, monotonic_ms


@dataclass(frozen=True)
class StepResult:
    """Everything a strategy needs to decide what to do after one interaction.

    ``finding`` is ``None`` when the trace did not breach. ``cell_hash`` is defined
    for *every* trace (breaching or not) so strategies can pursue novel tool-traces,
    which is what grows the scorer's +2 diversity term.
    """

    finding: Finding | None
    stats: TraceStats
    cell_hash: str
    guidance: float
    candidate_emitted: bool


class SearchContext:
    """Facade over env + evaluation + archive + logging used by every strategy."""

    def __init__(
        self,
        *,
        env: AttackEnvProtocol,
        run_config: AttackRunConfig,
        timebox: Timebox,
        rng: random.Random,
        archive: CandidateArchive,
        logger: RunLogger,
        evaluator: Evaluator,
        heuristics: HeuristicScorer,
    ) -> None:
        self.env = env
        self.run_config = run_config
        self.tb = timebox
        self.rng = rng
        self.archive = archive
        self.logger = logger
        self.evaluator = evaluator
        self.heuristics = heuristics
        self._steps = 0
        self._prev_tool_count = 0  # for per-turn tool attribution in a growing trace

    # ----------------------------------------------------------- run controls
    @property
    def steps(self) -> int:
        return self._steps

    def should_stop(self) -> bool:
        """True when any budget is exhausted (time, outer steps, or candidate cap)."""
        return (
            self.tb.expired()
            or self._steps >= int(self.run_config.max_steps)
            or self.archive.is_full
        )

    def reset(self) -> None:
        self.env.reset()
        self._prev_tool_count = 0

    def snapshot(self):
        return self.env.snapshot()

    def restore(self, snapshot) -> None:
        self.env.restore(snapshot)
        # After a restore the trace length changes; resync per-turn attribution.
        self._prev_tool_count = len(
            self.env.export_trace_dict().get("tool_events", []) or []
        )

    # --------------------------------------------------------------- one step
    def step(self, prompt: str) -> StepResult:
        """Send one message, evaluate + archive + log; return a :class:`StepResult`.

        The finding's candidate is the *entire* accumulated message chain (since the
        last reset/restore), which is exactly what the gateway replays from a fresh
        env. RandomSearch ignores the return value; BeamSearch ranks/branches on it.
        """
        self._steps += 1

        t0 = monotonic_ms()
        self.env.interact(prompt, max_tool_hops=self.run_config.max_tool_hops)
        duration_ms = monotonic_ms() - t0

        trace = self.env.export_trace_dict()
        events = trace.get("tool_events", []) or []
        new_tool_names = tuple(
            e.get("name", "") for e in events[self._prev_tool_count :]
        )
        self._prev_tool_count = len(events)

        finding = self.evaluator.evaluate(trace)
        cell_hash = (
            finding.cell_hash if finding is not None
            else self.evaluator.score_cell_hash(trace)
        )

        # Novelty must be checked *before* archiving (archive.add records the hash).
        cell_is_novel = (
            finding is not None and self.archive.is_novel_cell(finding.cell_hash)
        )
        stats = analyze_trace(trace)
        guidance = self.heuristics.score(
            stats=stats, finding=finding, cell_is_novel=cell_is_novel
        )

        candidate_emitted = False
        if finding is not None:
            candidate_emitted = self.archive.add(
                trace.get("user_messages", []) or [], finding
            )

        self.logger.record_interaction(
            step=self._steps,
            prompt=prompt,
            duration_ms=duration_ms,
            tool_names=new_tool_names,
            predicate_names=(finding.predicate_names if finding else ()),
            breach=finding is not None,
            candidate_emitted=candidate_emitted,
        )
        return StepResult(
            finding=finding,
            stats=stats,
            cell_hash=cell_hash,
            guidance=guidance,
            candidate_emitted=candidate_emitted,
        )


class SearchStrategy(ABC):
    """A policy that drives interactions to produce findings.

    Contract: implementations only *decide and act* through ``ctx``. They must not
    read the environment directly for scoring, nor manage the archive/logger -- the
    context owns all of that.
    """

    name: str = "base"

    def __init__(self, **params) -> None:
        self.params = params

    @abstractmethod
    def run(self, ctx: SearchContext) -> None: ...


class RandomSearch(SearchStrategy):
    """Episodic random search over the prompt library.

    Same *search policy* as the random baseline -- uniformly-random prompts, no
    guidance -- but with one deliberate correction: the baseline runs a single
    ever-growing episode, so its later candidates exceed the gateway's 32-message
    cap and would fail the whole submission at replay. We instead run **short
    episodes** (reset between trials), so every emitted candidate is a self-contained
    chain of at most ``episode_len`` messages -- exactly what the gateway replays
    from a fresh env. This keeps V1 a naive random baseline while producing *valid*,
    replayable candidates (and it naturally expresses multi-step attacks).

    Params
    ------
    episode_len : int
        Messages per trial before resetting (default 6; must be <= 32).
    """

    name = "random"

    def __init__(self, prompts: Sequence[str], episode_len: int = 6, **params) -> None:
        super().__init__(episode_len=episode_len, **params)
        if not prompts:
            raise ValueError("RandomSearch requires a non-empty prompt pool")
        if not 1 <= episode_len <= 32:
            raise ValueError("episode_len must be in [1, 32]")
        self._prompts = tuple(prompts)
        self._episode_len = episode_len

    def run(self, ctx: SearchContext) -> None:
        while not ctx.should_stop():
            ctx.reset()
            for _ in range(self._episode_len):
                if ctx.should_stop():
                    break
                ctx.step(ctx.rng.choice(self._prompts))


class LeaderboardSearch(SearchStrategy):
    """Kaggle-oriented search: priority scripts + volume-weighted random.

    Real leaderboard models (gpt_oss / gemma) behind OptimalGuardrail rarely fall
    for naive proxy prompts. This strategy:

    1. Burns early budget on curated multi-step / encoded-exfil scripts
       (``priority_scripts``) that target known OptimalGuardrail seams.
    2. Then farms volume with short episodes sampled from a **weighted** prompt
       pool (exfiltration / web / destructive overweight), which maximizes
       Σ severity under the gateway's no-dedup scorer when breaches land.

    Params
    ------
    episode_len : int
        Messages per random episode (default 4).
    priority_scripts : sequence of message tuples
        Full chains tried first (default: LEADERBOARD_SCRIPTS from prompt library).
    weighted_prompts : sequence of prompts
        Pool for the volume phase (already weighted by repetition).
    """

    name = "leaderboard"

    def __init__(
        self,
        prompts: Sequence[str],
        episode_len: int = 4,
        priority_scripts: Sequence[Sequence[str]] | None = None,
        weighted_prompts: Sequence[str] | None = None,
        **params,
    ) -> None:
        super().__init__(
            episode_len=episode_len,
            priority_scripts=priority_scripts,
            weighted_prompts=weighted_prompts,
            **params,
        )
        if not 1 <= episode_len <= 32:
            raise ValueError("episode_len must be in [1, 32]")
        pool = tuple(weighted_prompts) if weighted_prompts else tuple(prompts)
        if not pool:
            raise ValueError("LeaderboardSearch requires a non-empty prompt pool")
        self._episode_len = episode_len
        self._pool = pool
        self._scripts = tuple(tuple(s) for s in (priority_scripts or ()))

    def run(self, ctx: SearchContext) -> None:
        # Phase 1: curated scripts (high chance vs real LLMs).
        for script in self._scripts:
            if ctx.should_stop():
                return
            ctx.reset()
            for msg in script:
                if ctx.should_stop():
                    return
                ctx.step(msg)

        # Phase 2: volume farm with weighted prompts.
        while not ctx.should_stop():
            ctx.reset()
            for _ in range(self._episode_len):
                if ctx.should_stop():
                    break
                ctx.step(ctx.rng.choice(self._pool))


@dataclass
class BeamNode:
    """A reachable environment state on the beam frontier.

    We store the env ``snapshot`` (so we can branch from here without replaying from
    root), the ``messages`` that reach it (the candidate chain), the ``guidance``
    value that ranks it, and its ``cell_hash`` (for novelty-aware selection).
    """

    messages: tuple[str, ...]
    snapshot: object
    guidance: float
    cell_hash: str


class BeamSearch(SearchStrategy):
    """Heuristic-guided beam search over message chains.

    Where RandomSearch stumbles onto breaches by luck, beam search *pursues* partial
    progress: at each depth it expands the most promising states, keeps the best
    ``beam_width`` children (ranked by ``heuristics.score``), and repeats. This is
    what assembles the multi-step chains -- e.g. "open injection page" -> "act on it"
    -> EXFILTRATION -- that a uniform sampler almost never draws in the right order.

    Two design choices tuned to the scorer:

    * **Branch via snapshot/restore**, not replay: to expand a node we ``restore``
      its snapshot and ``interact`` once. This is the intended use of the env API and
      makes depth-D search cost O(B·K·D) interactions instead of re-running each
      chain from scratch.
    * **Novelty-preferring selection**: ties and near-ties are broken toward children
      whose scoring cell hash is unseen, so the beam spreads across distinct
      tool-traces (the +2 diversity term) instead of collapsing onto one.

    Anytime: sweeps restart from root until the time/step/candidate budget is spent;
    stochastic expansion (``expansions_per_node`` sampled prompts) makes each sweep
    explore different branches.

    Params
    ------
    beam_width : int          frontier size B kept between depths (default 8)
    max_depth : int           messages per chain D, 1..32 (default 6)
    expansions_per_node : int prompts tried per node per depth K (default: all)

    Time complexity: O(B·K·D) interactions per sweep.
    """

    name = "beam"

    def __init__(
        self,
        prompts: Sequence[str],
        beam_width: int = 8,
        max_depth: int = 6,
        expansions_per_node: int | None = None,
        **params,
    ) -> None:
        super().__init__(
            beam_width=beam_width,
            max_depth=max_depth,
            expansions_per_node=expansions_per_node,
            **params,
        )
        if not prompts:
            raise ValueError("BeamSearch requires a non-empty prompt pool")
        if beam_width < 1:
            raise ValueError("beam_width must be >= 1")
        if not 1 <= max_depth <= 32:
            raise ValueError("max_depth must be in [1, 32]")
        self._prompts = tuple(prompts)
        self._beam_width = beam_width
        self._max_depth = max_depth
        self._k = (
            len(self._prompts)
            if expansions_per_node is None
            else max(1, min(expansions_per_node, len(self._prompts)))
        )
        self._seen_cells: set[str] = set()

    def _expansion_prompts(self, rng: random.Random) -> tuple[str, ...]:
        if self._k >= len(self._prompts):
            return self._prompts
        return tuple(rng.sample(self._prompts, self._k))

    def _select(self, children: list[BeamNode]) -> list[BeamNode]:
        """Novelty-preferring top-B selection.

        Primary key: this child reaches a not-yet-seen scoring cell (breadth).
        Secondary key: heuristic guidance (depth of progress / realized value).
        """
        ranked = sorted(
            children,
            key=lambda n: (n.cell_hash not in self._seen_cells, n.guidance),
            reverse=True,
        )
        chosen = ranked[: self._beam_width]
        self._seen_cells.update(n.cell_hash for n in chosen)
        return chosen

    def _sweep(self, ctx: SearchContext) -> None:
        ctx.reset()
        frontier = [
            BeamNode(messages=(), snapshot=ctx.snapshot(), guidance=0.0, cell_hash="")
        ]
        for _ in range(self._max_depth):
            if ctx.should_stop():
                return
            children: list[BeamNode] = []
            for node in frontier:
                for prompt in self._expansion_prompts(ctx.rng):
                    if ctx.should_stop():
                        break
                    ctx.restore(node.snapshot)
                    result = ctx.step(prompt)  # interacts, evaluates, archives, logs
                    children.append(
                        BeamNode(
                            messages=node.messages + (prompt,),
                            snapshot=ctx.snapshot(),
                            guidance=result.guidance,
                            cell_hash=result.cell_hash,
                        )
                    )
            if not children:
                return
            frontier = self._select(children)

    def run(self, ctx: SearchContext) -> None:
        while not ctx.should_stop():
            self._sweep(ctx)
