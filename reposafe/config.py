from pathlib import Path
import yaml


def load_yaml(path: Path):
    if not path.exists():
        return {}
    with path.open("r", encoding="utf8") as f:
        return yaml.safe_load(f) or {}


def load_rules(root: Path):
    rules = {}
    rules_dir = root / "reposafe" / "rules"
    if rules_dir.exists():
        for p in rules_dir.glob("*.yml"):
            rules[p.stem] = load_yaml(p)
    return rules
