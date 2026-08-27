# CI Pipeline & Security Test Suite

This pipeline executes automated security, boundary, unit, and conformance checks.

## Pipeline Steps
1. **Dependency Installation**: `pytest`, `pytest-cov`, `pydantic`, `python-dotenv`, `cryptography`, `httpx`, `fastapi`.
2. **Security & Boundary Test Suite**: `tests/unit/test_config.py` (68 test cases testing sandbox limits, production URL rejections, live credential detection, userinfo tricks, adversarial IPs, and environment variable scanning).
3. **Architecture Conformance Validation**: All tests executed via `ci/run_ci.py` / `pytest`.

## Local & CI Invocation
```bash
python ci/run_ci.py
```
or
```bash
pytest -v tests/unit/
```
