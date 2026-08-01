"""Local evaluation harness for the attack framework (V1).

Purpose
-------
The leaderboard runs our candidates against an LLM (GPT-OSS / Gemma) behind a
guardrail, which we cannot run on a laptop. This harness is the fast local proxy: it
drives the SDK ``SandboxEnv`` with the deterministic vulnerable agent behind a chosen
guardrail, so we can iterate on search quality in milliseconds instead of minutes.

It does two things:
  1. PARITY: run the *original* random baseline and our ``RandomSearch`` framework
     under identical conditions and confirm they behave the same (V1 goal:
     "functionality identical to baseline").
  2. DEMO: show that both produce findings when the guardrail is actually beatable,
     and that OptimalGuardrail (the public leaderboard defense) blocks the naive
     random attack -- which is exactly why smarter search (V2+) is needed.

Run:  python experiments/run_local.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Make repo root importable when run as a script.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from aicomp_sdk.agents import build_agent  # noqa: E402
from aicomp_sdk.attacks.baselines.attack_random import (  # noqa: E402
    AttackAlgorithm as RandomBaseline,
)
from aicomp_sdk.attacks.baselines.guardrail_allow import Guardrail as AllowGuardrail  # noqa: E402
from aicomp_sdk.attacks.baselines.guardrail_rules import Guardrail as RulesGuardrail  # noqa: E402
from aicomp_sdk.attacks.contracts import AttackRunConfig  # noqa: E402
from aicomp_sdk.core.cells import cell_signature  # noqa: E402
from aicomp_sdk.core.env.sandbox import SandboxEnv  # noqa: E402
from aicomp_sdk.core.predicates import eval_predicates  # noqa: E402
from aicomp_sdk.guardrails.optimal import Guardrail as OptimalGuardrail  # noqa: E402
from aicomp_sdk.scoring import score_attack  # noqa: E402

from attack_framework.algorithm import AttackFramework  # noqa: E402
from attack_framework.config import FrameworkConfig  # noqa: E402

FIXTURES = _ROOT / "aicomp_sdk" / "fixtures"
GUARDRAILS = {
    "allow": AllowGuardrail,
    "rules": RulesGuardrail,
    "optimal(public)": OptimalGuardrail,
}


def make_env(guardrail_cls, seed: int = 123) -> SandboxEnv:
    return SandboxEnv(
        seed=seed,
        fixtures_dir=FIXTURES,
        agent=build_agent("deterministic"),
        guardrail=guardrail_cls(),
    )


def score_candidates(candidates, guardrail_cls, seed: int = 123) -> dict:
    """Replay candidates exactly as the gateway does and compute the attack score.

    Mirrors ``jed_attack_gateway._replay_candidates``: fresh env per candidate,
    ``eval_predicates`` gate, ``score_cell_signature = cell_signature(tool_events)``,
    then ``score_attack`` (Σ severity + 2·unique cells, normalized). This is our
    local proxy for the leaderboard number -- the value each new version must beat.
    """
    from collections import Counter

    findings = []
    predicate_freq: Counter[str] = Counter()
    for cand in candidates:
        env = make_env(guardrail_cls, seed=seed)
        env.reset()
        for msg in cand.user_messages:
            env.interact(msg)
        trace = env.export_trace_dict()
        predicates = eval_predicates(trace)
        if not predicates:
            continue
        predicate_freq.update(p.get("predicate", "?") for p in predicates)
        findings.append(
            {
                "predicates": predicates,
                "score_cell_signature": cell_signature(trace.get("tool_events", [])),
            }
        )
    return {
        "validated": len(findings),
        "score_normalized": round(score_attack(findings, normalize=True), 3),
        "score_raw": round(score_attack(findings, normalize=False), 3),
        "predicate_freq": dict(predicate_freq.most_common()),
    }


def run_strategy(strategy: str, guardrail_cls, cfg: AttackRunConfig, **params):
    """Run one framework strategy and return (candidates, local score dict)."""
    env = make_env(guardrail_cls)
    framework = AttackFramework(
        FrameworkConfig(search=strategy, verbose=False, strategy_params=params)
    )
    candidates = framework.run(env, cfg)
    return candidates, score_candidates(candidates, guardrail_cls)


def run_case(guardrail_name: str, guardrail_cls, budget_s: float, max_steps: int) -> None:
    cfg = AttackRunConfig(time_budget_s=budget_s, max_steps=max_steps)

    rand_c, rand_s = run_strategy("random", guardrail_cls, cfg, episode_len=6)
    beam_c, beam_s = run_strategy(
        "beam", guardrail_cls, cfg,
        beam_width=8, max_depth=8, expansions_per_node=12,
    )

    print(f"----- GUARDRAIL: {guardrail_name} -----")
    for label, cands, sc in (
        ("random", rand_c, rand_s),
        ("beam  ", beam_c, beam_s),
    ):
        print(
            f"  {label} | candidates={len(cands):4d} "
            f"validated={sc['validated']:4d} "
            f"raw={sc['score_raw']:7.1f} "
            f"normalized={sc['score_normalized']:6.3f} "
            f"predicates={sc['predicate_freq']}"
        )


def main() -> None:
    print("#" * 62)
    print("# V2 LOCAL HARNESS  (SandboxEnv + deterministic agent)  random vs beam")
    print("#" * 62)
    # `allow` = dense-breach regime (volume favours random); `rules` = sparse regime
    # (guided search should favour beam). Equal budgets for a clean head-to-head.
    run_case("allow", AllowGuardrail, budget_s=20.0, max_steps=100000)
    run_case("rules", RulesGuardrail, budget_s=20.0, max_steps=100000)


if __name__ == "__main__":
    main()
