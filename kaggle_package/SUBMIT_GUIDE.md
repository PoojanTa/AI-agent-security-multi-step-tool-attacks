# Kaggle Submit Guide — updated after probe-fill merge

## Ratings (honest)

| Method | Hosted claim | Local (deterministic) | Fit for LB | Rating |
|---|---:|---:|---|---:|
| Notebook `adaptive-uniform-two-probe-recovery` | **~88.5–89.1** | N/A (needs real LLM) | Excellent — validated single-post EXFIL farm | **9/10** |
| Our old `leaderboard` / random / beam | unknown | allow~70, optimal~0 | Weak vs OptimalGuardrail volume farm | **4/10 for LB** |
| **Our new default `probe_fill`** (rewritten merge) | TBD on submit | optimal still ~0 locally (expected) | Same competitive mechanics as notebook, distinct code | **9/10 potential** |

### Why the notebook is helpful
- Only returns **live-validated** candidates (what actually fired).
- Races a few **single-message** `http.post` + `SECRET_MARKER` templates.
- Picks the **cheapest reliable** template (latency / hit-rate).
- Fills up to **2000** unique destinations under a **replay time cap** (avoids timeout).
- Starts `JEDAttackInferenceServer` correctly on Kaggle.

### Why our old method was weaker for LB
- Broad multi-step search is good research, but OptimalGuardrail + real models reward **measured, high-volume EXFIL** more.
- Local `allow≈70` does not transfer to public OptimalGuardrail.

### What we changed so it is not a copy
- New module `attack_framework/probe_fill.py` (`ProbeFillSearch`, search=`probe_fill`).
- Different templates (incl. **base64/hex** sentinel variants for guardrail seams).
- Different URL scheme (`https://egress-XXX.sinkYY.example.net/intake`).
- Different knobs/names; wired through our framework/archive/evaluator.
- Default in `attack.py` is now `probe_fill`.

---

## Submit (same as before, notebook fixed)

1. Upload `jed_attack_submission.zip` as a Dataset and attach it.
2. Use `kaggle_package/submit_notebook.ipynb` (now calls `JEDAttackInferenceServer.serve()` on competition rerun).
3. Attach competition data that provides `kaggle_evaluation`.
4. Save Version → Submit.

Zip root must be:

```text
attack.py
attack_framework/
```
