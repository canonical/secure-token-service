"""OpenSpec integration package for Google's harness2 in canonical repositories."""

from .drift import check_drift, load_drift_config
from .init import init_repository
from .validation import validate_workspace

# Deterministic `c7` scripts materialised from the repository's single source
# of truth (`scripts/`); harness trees referencing them without carrying a
# copy are treated as runtime-provided (reserved) during surface validation.
RUNTIME_SCRIPTS = frozenset({"validate_openspec.py", "check_openspec_drift.py"})

__all__ = [
    "RUNTIME_SCRIPTS",
    "check_drift",
    "init_repository",
    "load_drift_config",
    "validate_workspace",
]
