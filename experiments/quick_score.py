"""Quick local score sample for the current AttackAlgorithm (deterministic proxy)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from aicomp_sdk.agents import build_agent
from aicomp_sdk.attacks.contracts import AttackRunConfig
from aicomp_sdk.core.cells import cell_signature
from aicomp_sdk.core.env.sandbox import SandboxEnv
from aicomp_sdk.core.predicates import eval_predicates
from aicomp_sdk.guardrails.optimal import Guardrail as OptimalGuardrail
from aicomp_sdk.scoring import score_attack
from aicomp_sdk.attacks.baselines.guardrail_allow import Guardrail as AllowGuardrail
from aicomp_sdk.attacks.baselines.guardrail_rules import Guardrail as RulesGuardrail

from attack import AttackAlgorithm

FIXTURES = _ROOT / "aicomp_sdk" / "fixtures"


def make_env(guardrail_cls, seed: int = 123) -> SandboxEnv:
    return SandboxEnv(
        seed=seed,
        fixtures_dir=FIXTURES,
        agent=build_agent("deterministic"),
        guardrail=guardrail_cls(),
    )


def replay_score(candidates, guardrail_cls, seed: int = 123) -> dict:
    findings = []
    pred_freq: dict[str, int] = {}
    for cand in candidates:
        env = make_env(guardrail_cls, seed=seed)
        env.reset()
        for msg in cand.user_messages:
            env.interact(msg)
        trace = env.export_trace_dict()
        predicates = eval_predicates(trace)
        if not predicates:
            continue
        for p in predicates:
            name = str(p.get("predicate", "?"))
            pred_freq[name] = pred_freq.get(name, 0) + 1
        findings.append(
            {
                "predicates": predicates,
                "score_cell_signature": cell_signature(trace.get("tool_events", [])),
            }
        )
    return {
        "candidates": len(candidates),
        "validated": len(findings),
        "raw": round(score_attack(findings, normalize=False), 3),
        "normalized": round(score_attack(findings, normalize=True), 3),
        "predicates": pred_freq,
    }


def main() -> None:
    budget_s = 15.0
    print("=" * 64)
    print("LOCAL SAMPLE SCORE  (deterministic agent proxy)")
    print(f"budget_s={budget_s}  search=random (default submission)")
    print("=" * 64)

    # Generate candidates once under AllowGuardrail (search env).
    gen_env = make_env(AllowGuardrail)
    attacker = AttackAlgorithm(config={"search": "random", "seed": 123})
    # Silence verbose end stats for cleaner output.
    candidates = attacker.run(
        gen_env,
        AttackRunConfig(time_budget_s=budget_s, max_steps=10**9, max_tool_hops=8),
    )
    print(f"\nGenerated candidates: {len(candidates)}")

    for name, gcls in (
        ("allow (easy proxy)", AllowGuardrail),
        ("rules (medium)", RulesGuardrail),
        ("optimal (public LB)", OptimalGuardrail),
    ):
        # Re-run generation under matching guardrail for fairer local estimate,
        # except we also report replay of the allow-generated set vs optimal.
        env = make_env(gcls)
        cands = AttackAlgorithm(config={"search": "random", "seed": 123}).run(
            env,
            AttackRunConfig(time_budget_s=budget_s, max_steps=10**9, max_tool_hops=8),
        )
        sc = replay_score(cands, gcls)
        print(
            f"\n[{name}]\n"
            f"  generated={sc['candidates']:4d}  validated={sc['validated']:4d}\n"
            f"  raw={sc['raw']:8.1f}  normalized={sc['normalized']:7.3f}\n"
            f"  predicates={sc['predicates']}"
        )

    print("\nNOTE: deterministic proxy cannot breach OptimalGuardrail.")
    print("Kaggle score uses real gpt_oss/gemma — local optimal≈0 is expected.")
    print("=" * 64)


if __name__ == "__main__":
    main()
