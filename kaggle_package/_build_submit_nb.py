"""Build self-contained Kaggle submit notebooks from attack_standalone.py.

Default (k=1, single-post):  kaggle_package/submit_notebook.ipynb
Modest-density A/B (k=2):     kaggle_package/submit_notebook_k2.ipynb

The source file keeps MULTIPOST_K = 1 (the diagnosed winner: a dense single-post farm
that finishes replay with headroom). The k=2 notebook is produced by rewriting only
that constant inside the embedded %%writefile cell — do not hand-edit the notebooks;
re-run this script after changing attack_standalone.py.

  python kaggle_package/_build_submit_nb.py
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STANDALONE = ROOT / "attack_standalone.py"

SERVER_SRC = r'''import csv
import glob
import importlib.util
import os
import py_compile
import sys
from pathlib import Path

COMP = "ai-agent-security-multi-step-tool-attacks"
IS_RERUN = os.getenv("KAGGLE_IS_COMPETITION_RERUN")

candidates = [
    f"/kaggle/input/competitions/{COMP}",
    f"/kaggle/input/{COMP}",
    *glob.glob("/kaggle/input/**/kaggle_evaluation", recursive=True),
]
sdk_root = None
for p in candidates:
    root = p
    if p.endswith("kaggle_evaluation"):
        root = str(Path(p).parent)
    if os.path.isdir(os.path.join(root, "kaggle_evaluation")):
        sdk_root = root
        break
if sdk_root is None:
    raise FileNotFoundError("Competition data with kaggle_evaluation not found under /kaggle/input")
if sdk_root not in sys.path:
    sys.path.insert(0, sdk_root)
print("SDK path:", sdk_root)

ATTACK_PATH = "/kaggle/working/attack.py"
py_compile.compile(ATTACK_PATH, doraise=True)
spec = importlib.util.spec_from_file_location("attack_candidate", ATTACK_PATH)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

smoke = module.AttackAlgorithm().run(None, None)
assert smoke
assert all(1 <= len(c.user_messages) <= 32 for c in smoke)
assert all(isinstance(m, str) and 0 < len(m) <= 2000 for c in smoke for m in c.user_messages)
print("attack.py compile/import/structure smoke: PASS")
print("MULTIPOST_K =", getattr(module, "MULTIPOST_K", "?"))

from kaggle_evaluation.jed_attack_134815.jed_attack_inference_server import JEDAttackInferenceServer
server = JEDAttackInferenceServer()

if IS_RERUN:
    server.serve()
else:
    with open("/kaggle/working/submission.csv", "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["Id", "Score"])
        writer.writerows([
            ["gpt_oss_public", 0.0],
            ["gpt_oss_private", 0.0],
            ["gemma_public", 0.0],
            ["gemma_private", 0.0],
        ])
    print("placeholder submission.csv written")
    print("NEXT: Internet OFF -> Save Version -> Submit that version")
'''


def _md(k: int) -> str:
    label = "DEFAULT (MULTIPOST_K=1, single-post)" if k == 1 else f"A/B only (MULTIPOST_K={k})"
    when = (
        "Submit this first."
        if k == 1
        else "Submit only after the single-post run scores and has no timeout/INVALID."
    )
    return f"""# JED probe-fill submission — {label}

## CRITICAL before Save Version
1. Right sidebar → **Settings**
2. Set **Internet = Off** (Submit is blocked if Internet is on)
3. Do **not** need our dataset — this notebook writes `attack.py` itself
4. Keep competition data attached

## This variant
- Embedded attack uses **MULTIPOST_K = {k}**
- {when}
- Rebuild from source: `python kaggle_package/_build_submit_nb.py`

## Flow
1. Write `/kaggle/working/attack.py`
2. Smoke-check AttackAlgorithm contract
3. Start `JEDAttackInferenceServer`
4. On competition re-run, gateway writes the real `submission.csv`

## Submit
1. Internet **OFF**
2. **Save Version → Save & Run All**
3. Competition Submit → select this notebook version → output `submission.csv`
"""


def lines(text: str) -> list[str]:
    return [ln + "\n" for ln in text.splitlines()]


def _with_k(attack: str, k: int) -> str:
    """Rewrite MULTIPOST_K assignment for an A/B notebook without touching source file."""
    replaced, n = re.subn(
        r"^MULTIPOST_K = \d+\s*$",
        f"MULTIPOST_K = {k}",
        attack,
        count=1,
        flags=re.MULTILINE,
    )
    if n != 1:
        raise RuntimeError("could not rewrite MULTIPOST_K in attack_standalone.py")
    return replaced


def build_notebook(attack: str, k: int, out: Path) -> None:
    write_src = "%%writefile /kaggle/working/attack.py\n" + attack
    nb = {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3",
            },
            "language_info": {"name": "python"},
            "kaggle": {
                "accelerator": "none",
                "isInternetEnabled": False,
                "language": "python",
                "sourceType": "notebook",
                "isGpuEnabled": False,
            },
        },
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": lines(_md(k))},
            {"cell_type": "markdown", "metadata": {}, "source": ["## 1) Write attack.py\n"]},
            {
                "cell_type": "code",
                "metadata": {},
                "execution_count": None,
                "outputs": [],
                "source": lines(write_src),
            },
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": ["## 2) Start evaluation server\n"],
            },
            {
                "cell_type": "code",
                "metadata": {},
                "execution_count": None,
                "outputs": [],
                "source": lines(SERVER_SRC),
            },
        ],
    }
    out.write_text(json.dumps(nb, indent=1), encoding="utf-8")
    print("wrote", out, "MULTIPOST_K=", k, "attack_chars", len(attack))


def main() -> None:
    source = STANDALONE.read_text(encoding="utf-8")
    # Source of truth stays at whatever MULTIPOST_K is in the file (default 1).
    m = re.search(r"^MULTIPOST_K = (\d+)\s*$", source, flags=re.MULTILINE)
    if not m:
        raise RuntimeError("MULTIPOST_K not found in attack_standalone.py")
    default_k = int(m.group(1))
    if default_k != 1:
        print(
            "WARNING: attack_standalone.py MULTIPOST_K=%d (expected 1 for default submit)"
            % default_k
        )

    build_notebook(source, default_k, ROOT / "submit_notebook.ipynb")
    build_notebook(_with_k(source, 2), 2, ROOT / "submit_notebook_k2.ipynb")


if __name__ == "__main__":
    main()
