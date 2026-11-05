from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceRecord:
    name: str
    display_name: str
    binary_path: str | None = None
    start_type: str | None = None
    run_as_account: str | None = None
    state: str | None = None
    collection_errors: tuple[str, ...] = ()
    can_change_config: bool | None = None

@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    severity: str
    confidence: str
    target: str
    description: str
    evidence: tuple[str, ...]
    remediation: str
    cwe_id: str | None = None
    limitations: tuple[str, ...] = ()

@dataclass(frozen=True)
class Token:
    account_name: str
    user_SID: str | None = None
    is_elevated: bool | None = None
    integrity_level: str | None = None
    is_local_admin: bool | None = None
    collection_errors: tuple[str, ...] = ()