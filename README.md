# JED Multi-Step Tool-Attack Framework

A research-grade, incrementally-improvable attack framework for the Kaggle
competition *AI Agent Security — Multi-Step Tool Attacks*. The goal is not a single
`attack.py`, but a modular search platform where each new algorithm (beam,
evolutionary, novelty, MCTS) is a drop-in strategy selected by config.

> Ground-truth mechanics (scoring, caps, guardrail seams) live in
> [`docs/mechanics.md`](docs/mechanics.md). Read that first — every design choice
> here traces back to it.

## Architecture

```
attack.py                     # competition entrypoint (thin shim + sys.path fix)
attack_framework/
  config.py                   # FrameworkConfig: strategy switch + knobs (pure data)
  utils.py                    # Timebox, signatures (dependency-light)
  logger.py                   # per-interaction records + end-of-run statistics
  prompt_library.py           # categorized attacker prompts (data, not code)
  trace_analyzer.py           # typed view over env.export_trace_dict()
  evaluator.py                # predicate/severity/score-cell scoring (mirrors scorer)
  heuristics.py               # configurable value function to guide search
  archive.py                  # de-duplicated, capped store of findings (the product)
  search.py                   # SearchStrategy interface + SearchContext + RandomSearch
  algorithm.py                # orchestrator: wires components, runs the strategy
experiments/run_local.py      # local harness: parity vs baseline + local scoring
docs/  notes/
```

**Dependency direction:** `attack.py` → `algorithm` → (`search` → `SearchContext` →
everything). A new strategy touches only `search.py` + one line of
`algorithm.build_strategy`.

## How to run locally

```bash
# smoke test (SandboxEnv + deterministic proxy + OptimalGuardrail)
PYTHONIOENCODING=utf-8 python attack.py

# full harness: baseline parity + local attack score across guardrails
PYTHONIOENCODING=utf-8 python experiments/run_local.py
```

Local runs use the deterministic proxy agent (the real GPT-OSS/Gemma targets can't
run on a laptop). The framework is agent-agnostic, so behavior transfers.

## Switching search strategy

```python
from attack_framework.config import FrameworkConfig
FrameworkConfig(search="random")   # V1 (only option today)
# later: search="beam" | "evolution" | "hybrid"  — no changes to attack.py
```

## Version roadmap

| Ver | Theme                     | Status |
|-----|---------------------------|--------|
| V1  | Clean, instrumented baseline (episodic random), valid candidates, local scoring | ✅ done |
| V2  | Beam search + heuristic ordering (snapshot branching, novelty selection) | ✅ done — see finding below |
| V3  | Prompt mutation / **volume amplification** (reprioritised as highest-leverage) | next |
| V4  | Evolutionary search        | planned |
| V5  | Hybrid (volume-random farm + beam discovery + novelty) | planned |
| V6  | Runtime opt (snapshots, dedup, diversity) | planned |

**V2 finding (measured):** the scorer sums severity over *every* finding with no
dedup, so **volume of findings dominates**. Pure beam trades volume for depth and
therefore *loses* to volume-random on every proxy-breachable guardrail at equal
budget. Beam only pays off when breaches are rare/deep (the real LLM +
OptimalGuardrail regime, which the local proxy can't simulate). So the default
submission strategy stays `random`; beam is kept as the discovery arm of the future
hybrid. Full analysis: [`notes/v2.md`](notes/v2.md).

## Current status (measured)

Local proxy, equal 20s budget, `random` (episodic) vs `beam` (width 8 / depth 8):

| Guardrail        | random norm (findings) | beam norm (findings) |
|------------------|-----------------------:|---------------------:|
| allow (trivial)  | **56.24** (393)        | 16.71 (95)           |
| rules            | **12.07** (97)         | 7.04 (58)            |
| optimal (public) | 0 (0)                  | 0 (0)                |

Both strategies: 100% replay fidelity (validated == candidates), all ≤ 32 messages.
Random wins on volume (no-dedup scoring); both score **0** vs the public guardrail on
the proxy — beating it requires the real LLM target + encoded payloads, validated on
the leaderboard. See [`notes/v2.md`](notes/v2.md).
