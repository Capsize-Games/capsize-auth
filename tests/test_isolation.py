"""Guards the package's standalone contract.

The package must never import the application it was extracted from —
that is the whole point of the storage seam.  This test makes the
verification a permanent part of the suite instead of a one-off grep.
"""

from __future__ import annotations

from pathlib import Path

# Assembled at runtime rather than written literally: the published repo
# must contain no occurrence of the application package name at all, and
# this guard file is part of that repo.
FORBIDDEN_TOKEN = "_".join(("airunner", "services"))


def _python_files() -> list[Path]:
    """Return every Python file in the package, excluding this test."""
    root = Path(__file__).resolve().parents[1]
    self_path = Path(__file__).resolve()
    return sorted(p for p in root.rglob("*.py") if p != self_path)


def test_package_imports_nothing_from_the_application() -> None:
    """No source or test file references the source application."""
    offenders = [
        str(path) for path in _python_files()
        if FORBIDDEN_TOKEN in path.read_text(encoding="utf-8")
    ]
    assert offenders == [], (
        f"{FORBIDDEN_TOKEN} referenced in: {offenders}"
    )


def test_package_imports_standalone() -> None:
    """Every public module imports with only this package installed."""
    import importlib

    for name in (
        "uwuchat_auth_core",
        "uwuchat_auth_core.account_status",
        "uwuchat_auth_core.auth_provider",
        "uwuchat_auth_core.base",
        "uwuchat_auth_core.crypto.data_encryption",
        "uwuchat_auth_core.crypto.dek_cache",
        "uwuchat_auth_core.dependencies",
        "uwuchat_auth_core.geoblock",
        "uwuchat_auth_core.geoip",
        "uwuchat_auth_core.jwt",
        "uwuchat_auth_core.limiter",
        "uwuchat_auth_core.middleware",
        "uwuchat_auth_core.models",
        "uwuchat_auth_core.oauth",
        "uwuchat_auth_core.oauth_capabilities_routes",
        "uwuchat_auth_core.password_policy",
        "uwuchat_auth_core.password_reset_token",
        "uwuchat_auth_core.passwords",
        "uwuchat_auth_core.reference",
        "uwuchat_auth_core.storage",
        "uwuchat_auth_core.twitch_helix",
        "uwuchat_auth_core.twitch_oauth",
    ):
        assert importlib.import_module(name) is not None
