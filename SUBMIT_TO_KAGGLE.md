# Exact Kaggle submit (fixed / official pattern)

This competition does **not** want a dataset zip workflow as the main path.
Winning notebooks do this:

1. Notebook writes `/kaggle/working/attack.py` with `%%writefile`
2. Starts `JEDAttackInferenceServer`
3. **Internet = OFF**
4. Save Version → Submit that notebook version (`submission.csv`)

Use: `kaggle_package/submit_notebook.ipynb`

---

## Fix your current error (“Cannot submit … disable internet”)

1. Open your notebook on Kaggle
2. Right side → **Settings** (gear)
3. **Internet → Off**
4. **Save Version → Save & Run All** again
5. Then Submit that **new** version

Old versions saved with Internet ON cannot be submitted.

---

## Clean submit from scratch (recommended)

1. Competition → **Code → New Notebook**
2. Settings → **Internet Off**
3. Upload / paste cells from local file:  
   `kaggle_package/submit_notebook.ipynb`
4. You do **not** need the `jed-attack-submission` dataset
5. Keep competition data (auto) so `kaggle_evaluation` exists
6. Run all cells → should print `smoke: PASS` and write placeholder `submission.csv`
7. **Save Version → Save & Run All**
8. Competition → Submit → choose that notebook version → Output File `submission.csv`

On real scoring re-run, Kaggle sets `KAGGLE_IS_COMPETITION_RERUN` and `server.serve()` produces the real score file.

---

## What was wrong before

| Mistake | Why it failed |
|---|---|
| Dataset + copy files | Extra complexity; not how top notebooks work |
| Internet ON | Competition forbids internet on submit |
| Relying on placeholder score locally | Real score only on competition re-run |

---

## Local files

- `kaggle_package/submit_notebook.ipynb` ← upload this
- `kaggle_package/attack_standalone.py` ← source embedded into the notebook
