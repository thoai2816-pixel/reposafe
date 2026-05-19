
# RepoSafe

Lightweight open-source repository security scanning tool.

Quick start

1. Create and activate a Python 3.10+ virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies from `requirements.txt`:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

3. Run tests:

```bash
pytest -q
```

4. Run RepoSafe (examples):

```bash
python -m reposafe.cli scan ./demo_repo --format html --out report.html
python -m reposafe.cli secrets ./demo_repo
```

Notes:

- If you prefer editable install, run `pip install -e .` to make local changes available to Python.
- For CI or packaging, use the `pyproject.toml` provided.

