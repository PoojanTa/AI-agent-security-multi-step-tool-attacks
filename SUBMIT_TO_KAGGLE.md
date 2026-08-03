# Exact Kaggle submit (V5 — hardened single-post)

This competition does **not** want a dataset zip workflow as the main path.
Winning notebooks do this:

1. Notebook writes `/kaggle/working/attack.py` with `%%writefile`
2. Starts `JEDAttackInferenceServer`
3. **Internet = OFF**
4. Save Version → Submit that notebook version (`submission.csv`)

---

## Why V5 (read this before submitting)

Two real hosted runs on this account told us exactly what to fix:

| Date | Notebook | Result | Cause |
|---|---|---|---|
| Aug 01 | single-post @ `REPLAY_SAFE=0.99` | **blank / INVALID** | replay rebuilds a fresh env per candidate that generation never pays → a fill sized to 0.99·9000 s overran the 9000 s replay wall → score 0 |
| Aug 02 | multipost `k=4` | **63.99** | the real model emitted far fewer than 4 posts/message while burning hops, so total firing posts (the only scoring term) *dropped* vs a dense single-post farm |

V5 default = **dense single-post farm, hardened against the replay wall**:
`REPLAY_SAFE=0.90` + a per-candidate env-rebuild pad, so replay finishes with a real
buffer and never goes INVALID. Multipost is demoted to an opt-in A/B at **k=2** only.

---

## What to submit now vs later

| When | File | `MULTIPOST_K` | Notes |
|---|---|---:|---|
| **Now (first)** | `kaggle_package/submit_notebook.ipynb` | **1** | Hardened single-post farm; finishes replay with headroom |
| **Later (A/B)** | `kaggle_package/submit_notebook_k2.ipynb` | **2** | Modest density probe; submit only after k=1 completes and shows replay headroom |
| Fallback | rebuild with a lower `REPLAY_SAFE_SINGLE` in source | 1 | If k=1 still shows a timeout, cut the budget further |

Rebuild both notebooks after editing the source:

```powershell
python kaggle_package/_build_submit_nb.py
```

Source of truth: `kaggle_package/attack_standalone.py` (keeps `MULTIPOST_K = 1`).
The k=2 notebook rewrites only that constant inside the embedded cell.

---

## Clean submit from scratch (recommended)

1. Competition → **Code → New Notebook**
2. Settings → **Internet Off**
3. Upload / paste cells from: `kaggle_package/submit_notebook.ipynb`
4. You do **not** need the `jed-attack-submission` dataset
5. Keep competition data (auto) so `kaggle_evaluation` exists
6. Run all cells → should print `smoke: PASS`, `MULTIPOST_K = 1`, and write placeholder `submission.csv`
7. **Save Version → Save & Run All**
8. Competition → Submit → choose that notebook version → Output File `submission.csv`

On real scoring re-run, Kaggle sets `KAGGLE_IS_COMPETITION_RERUN` and `server.serve()` produces the real score file.

---

## Fix "Cannot submit … disable internet"

1. Open your notebook on Kaggle
2. Right side → **Settings** (gear)
3. **Internet → Off**
4. **Save Version → Save & Run All** again
5. Then Submit that **new** version

Old versions saved with Internet ON cannot be submitted.

---

## After the k=1 result

- Score lands (e.g. low-to-mid 80s) and no timeout → the fix worked; optionally A/B
  `submit_notebook_k2.ipynb` for the modest density upside
- **Still INVALID / timeout** → lower `REPLAY_SAFE_SINGLE` (e.g. 0.85) in
  `attack_standalone.py` and rebuild; do **not** raise k
- k=2 scores lower than k=1 → keep k=1 (confirms the Aug-02 density regression)

---

## Local files

- `kaggle_package/submit_notebook.ipynb` ← **submit this now** (k=1)
- `kaggle_package/submit_notebook_k2.ipynb` ← submit later (k=2 A/B)
- `kaggle_package/attack_standalone.py` ← source embedded into the notebooks
- `kaggle_package/_build_submit_nb.py` ← rebuild both notebooks
