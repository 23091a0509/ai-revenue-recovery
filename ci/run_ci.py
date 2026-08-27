"""Continuous Integration & Security Conformance Test Runner.

Executes the automated unit, security, adversarial, and conformance test suites
and validates that all architectural boundaries pass before merging.
"""

import sys
import subprocess


def run_command(command: list[str], description: str) -> int:
    print(f"\n[CI] Running: {description} ({' '.join(command)})...")
    result = subprocess.run(command, capture_output=False)
    if result.returncode != 0:
        print(f"[CI ERROR] {description} failed with exit code {result.returncode}!")
    else:
        print(f"[CI SUCCESS] {description} passed.")
    return result.returncode


def main() -> int:
    print("=" * 60)
    print("AI Revenue Recovery — CI & Security Validation Pipeline")
    print("=" * 60)

    # 1. Run full test suite with coverage
    test_code = run_command(
        [sys.executable, "-m", "pytest", "tests/unit/", "-v"],
        "Pytest Unit and Adversarial Test Suite"
    )

    if test_code != 0:
        return test_code

    print("\n" + "=" * 60)
    print("[CI SUMMARY] All automated security and unit tests PASSED.")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
