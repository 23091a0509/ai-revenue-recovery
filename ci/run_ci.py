"""Continuous Integration & Security Conformance Test Runner.

Executes the automated unit, security, adversarial, and conformance test suites
and validates that all architectural boundaries pass before merging.
"""

import sys
import subprocess


def run_command(command: list[str], description: str) -> int:
    print(f"\n[CI] Running: {description} ({' '.join(command)})...")
    result = subprocess.run(command)
    if result.returncode != 0:
        print(f"[CI ERROR] {description} failed with exit code {result.returncode}!")
    else:
        print(f"[CI SUCCESS] {description} passed.")
    return result.returncode


def main() -> int:
    print("=" * 70)
    print("AI Revenue Recovery — Full CI & Conformance Pipeline")
    print("=" * 70)

    # 1. Run unit tests
    unit_code = run_command(
        [sys.executable, "-m", "pytest", "tests/unit/", "-v"],
        "Unit and Safeguard Test Suite (tests/unit/)"
    )
    if unit_code != 0:
        return unit_code

    # 2. Run dedicated security tests
    sec_code = run_command(
        [sys.executable, "-m", "pytest", "tests/security/", "-v"],
        "Security & Boundary Test Suite (tests/security/)"
    )
    if sec_code != 0:
        return sec_code

    # 3. Run architecture conformance tests
    conf_code = run_command(
        [sys.executable, "-m", "pytest", "tests/conformance/", "-v"],
        "Architecture Conformance Test Suite (tests/conformance/)"
    )
    if conf_code != 0:
        return conf_code

    print("\n" + "=" * 70)
    print("[CI SUMMARY] All Unit, Security, and Conformance Test Suites PASSED.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
