# RepoSafe Integration Demo

This directory demonstrates how another Python program can import RepoSafe as a library and reuse its scanning capability without invoking the CLI.

Run from the repository root:

```bash
python examples/integration_demo/third_party_scan.py
```

The script scans `examples/vulnerable_repo`, prints a structured summary, and shows several findings as JSON-like records. It can be used as evidence that RepoSafe can be referenced and integrated by other software.
