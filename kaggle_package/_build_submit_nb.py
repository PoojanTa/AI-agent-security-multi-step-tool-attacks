import json
from pathlib import Path

attack = Path("kaggle_package/attack_standalone.py").read_text(encoding="utf-8")
write_src = "%%writefile /kaggle/working/attack.py\n" + attack

server_src = r'''import csv
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

md0 = """# JED probe-fill submission (official pattern)

## CRITICAL before Save Version
1. Right sidebar → **Settings**
2. Set **Internet = Off** (Submit is blocked if Internet is on)
3. Do **not** need our dataset — this notebook writes `attack.py` itself
4. Keep competition data attached

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


def lines(text: str):
    # Keep final newline style notebook-friendly
    return [ln + "\n" for ln in text.splitlines()]


nb = {
    "nbformat": 4,
    "nbformat_minor": 5,
    "metadata": {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
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
        {"cell_type": "markdown", "metadata": {}, "source": lines(md0)},
        {"cell_type": "markdown", "metadata": {}, "source": ["## 1) Write attack.py\n"]},
        {
            "cell_type": "code",
            "metadata": {},
            "execution_count": None,
            "outputs": [],
            "source": lines(write_src),
        },
        {"cell_type": "markdown", "metadata": {}, "source": ["## 2) Start evaluation server\n"]},
        {
            "cell_type": "code",
            "metadata": {},
            "execution_count": None,
            "outputs": [],
            "source": lines(server_src),
        },
    ],
}

out = Path("kaggle_package/submit_notebook.ipynb")
out.write_text(json.dumps(nb, indent=1), encoding="utf-8")
print("wrote", out, "attack_chars", len(attack))
