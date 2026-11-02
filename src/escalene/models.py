"""Data models used by Escalene.

These models represent collected evidence only. They do not decide whether a
configuration is vulnerable or exploitable.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceRecord:
    """Observed metadata for one Windows service."""

    name: str
    display_name: str
    binary_path: str | None = None
    start_type: str | None = None
    run_as_account: str | None = None
    state: str | None = None
    collection_errors: tuple[str, ...] = ()