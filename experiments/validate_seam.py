"""Seam-validation harness: measure the sentinel-exfil pipeline locally.

The deterministic proxy cannot fire the ``SECRET_MARKER`` exfil channel, so until now
every strategy scored 0 locally and the Kaggle submission was a blind bet. This
harness swaps in ``CompliantVulnerableAgent`` — an instruction-following LLM stand-in
— and drives the real ``SandboxEnv`` + ``OptimalGuardrail`` (the public leaderboard
defense). It answers three questions with numbers instead of hope:

  1. Does a clean-URL ``http.post`` carrying ``SECRET_MARKER`` actually pass
     OptimalGuardrail and fire EXFILTRATION?  (seam proof)
  2. What normalized score does each strategy project *under compliance*?
  3. Does the sentinel strategy (``probe_fill``) beat the vague prompt-library
     strategies (``leaderboard`` / ``random``) that rely on reading a blocked secret?

It also prints the deterministic-agent baseline (≈0 vs optimal) as the control: the
contrast is the whole justification for the sentinel design.

Run:  PYTHONIOENCODING=utf-8 python experiments/validate_seam.py
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from aicomp_sdk.agents import build_agent  # noqa: E402
from aicomp_sdk.attacks.baselines.guardrail_allow import Guardrail as AllowGuardrail  # noqa: E402
from aicomp_sdk.attacks.contracts import AttackRunConfig  # noqa: E402
from aicomp_sdk.core.cells import cell_signature  # noqa: E402
from aicomp_sdk.core.env.sandbox import SandboxEnv  # noqa: E402
from aicomp_sdk.core.predicates import eval_predicates  # noqa: E402
from aicomp_sdk.guardrails.optimal import Guardrail as OptimalGuardrail  # noqa: E402
from aicomp_sdk.scoring import score_attack  # noqa: E402

from attack_framework.algorithm import AttackFramework  # noqa: E402
from attack_framework.config import FrameworkConfig  # noqa: E402
from experiments.compliant_agent import CompliantVulnerableAgent  # noqa: E402

FIXTURES = _ROOT / "aicomp_sdk" / "fixtures"

# Fast-run overrides so probe_fill's wall-clock reserve does not swallow a short
# local budget. The compliant agent runs in well under a millisecond per turn, so a
# tiny reserve is safe here (it is NOT what we submit — the shipped defaults keep the
# real 60s+ reserve for the leaderboard's slow LLM turns).
_PROBE_FILL_FAST = {
    "reserve_s": 1.0,
    "reserve_mult": 0.05,  # neutralise the 24s `slowest` floor for the fast dev agent
    "warmup_cap_s": 1.0,
    "race_rounds": 2,
    "replay_budget_s": 9000.0,
}


def make_env(agent_name: str, guardrail_cls, seed: int = 123) -> SandboxEnv:
    agent = (
        CompliantVulnerableAgent()
        if agent_name == "compliant"
        else build_agent("deterministic")
    )
    return SandboxEnv(
        seed=seed,
        fixtures_dir=FIXTURES,
        agent=agent,
        guardrail=guardrail_cls(),
    )


def replay_score(candidates, agent_name: str, guardrail_cls, seed: int = 123) -> dict:
    """Replay candidates exactly as the gateway does, but against a chosen agent.

    Fresh env per candidate; ``eval_predicates`` gate; cell signature over tool
    events; ``score_attack`` for the normalized/raw number. Replaying against the
    *same* agent used for generation is the faithful estimate of "if the model
    complies, this is the score".
    """
    findings = []
    pred_freq: dict[str, int] = {}
    for cand in candidates:
        env = make_env(agent_name, guardrail_cls, seed=seed)
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
        "raw": round(score_attack(findings, normalize=False), 1),
        "normalized": round(score_attack(findings, normalize=True), 3),
        "predicates": pred_freq,
    }


def run_case(
    strategy: str,
    agent_name: str,
    guardrail_cls,
    *,
    budget_s: float,
    max_steps: int,
    params: dict | None = None,
) -> dict:
    env = make_env(agent_name, guardrail_cls)
    framework = AttackFramework(
        FrameworkConfig(search=strategy, verbose=False, strategy_params=params or {})
    )
    t0 = time.monotonic()
    candidates = framework.run(
        env, AttackRunConfig(time_budget_s=budget_s, max_steps=max_steps, max_tool_hops=8)
    )
    gen_s = time.monotonic() - t0
    score = replay_score(candidates, agent_name, guardrail_cls)
    score["gen_s"] = round(gen_s, 2)
    return score


def _print(label: str, sc: dict) -> None:
    print(
        f"  {label:<34} cand={sc['candidates']:5d} valid={sc['validated']:5d} "
        f"raw={sc['raw']:9.1f} norm={sc['normalized']:7.2f} "
        f"gen={sc['gen_s']:5.2f}s  {sc['predicates']}"
    )


def main() -> None:
    budget_s = float(os.environ.get("VALIDATE_BUDGET_S", "40"))
    max_steps = int(os.environ.get("VALIDATE_MAX_STEPS", "1600"))

    print("#" * 78)
    print("# SEAM VALIDATION — compliant LLM stand-in vs OptimalGuardrail (public LB)")
    print(f"# budget_s={budget_s}  max_steps={max_steps}")
    print("#" * 78)

    print("\n[A] CONTROL — deterministic proxy (cannot emit SECRET_MARKER):")
    _print(
        "deterministic × optimal / probe_fill",
        run_case("probe_fill", "deterministic", OptimalGuardrail,
                 budget_s=budget_s, max_steps=max_steps, params=_PROBE_FILL_FAST),
    )

    print("\n[B] SEAM PROOF — compliant LLM stand-in vs OptimalGuardrail:")
    _print(
        "compliant × optimal / probe_fill",
        run_case("probe_fill", "compliant", OptimalGuardrail,
                 budget_s=budget_s, max_steps=max_steps, params=_PROBE_FILL_FAST),
    )
    _print(
        "compliant × optimal / leaderboard",
        run_case("leaderboard", "compliant", OptimalGuardrail,
                 budget_s=budget_s, max_steps=max_steps),
    )
    _print(
        "compliant × optimal / random",
        run_case("random", "compliant", OptimalGuardrail,
                 budget_s=budget_s, max_steps=max_steps),
    )

    print("\n[C] REFERENCE — compliant LLM vs allow guardrail (upper bound):")
    _print(
        "compliant × allow / probe_fill",
        run_case("probe_fill", "compliant", AllowGuardrail,
                 budget_s=budget_s, max_steps=max_steps, params=_PROBE_FILL_FAST),
    )

    print("\nReading:")
    print("  * [A]≈0 and [B].probe_fill>0 proves the guardrail only inspects http.post")
    print("    'url' (not 'data'), so a clean-URL SECRET_MARKER post scores EXFILTRATION.")
    print("  * probe_fill >> leaderboard/random under compliance: the vague prompts try")
    print("    to read secret.txt (blocked by optimal); the sentinel channel needs no read.")
    print("  * Numbers are the ceiling under 'model complied'; real GPT-OSS/Gemma")
    print("    compliance is the remaining leaderboard unknown.")


if __name__ == "__main__":
    main()
