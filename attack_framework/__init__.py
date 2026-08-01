"""Research-grade attack framework for the JED multi-step tool-attack competition.

The package is intentionally layered so that each version of the roadmap adds a
*single* well-isolated component:

    config        -> runtime knobs + strategy selection (no logic)
    utils         -> timing + signature helpers (no framework deps)
    logger        -> per-interaction records + end-of-run statistics
    prompt_library-> categorized attack prompts (data, not code)
    trace_analyzer-> structured view over env.export_trace_dict()
    evaluator     -> predicate/severity/cell-signature scoring (mirrors the scorer)
    heuristics    -> configurable value function for guiding search
    archive       -> de-duplicated store of findings (the product we ship)
    search        -> SearchStrategy interface + concrete strategies (V1: Random)
    algorithm     -> orchestrator that wires everything and runs a strategy

Only ``algorithm.AttackFramework`` is imported by the competition ``attack.py``.
Everything else is independently testable.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "1.0.0"
