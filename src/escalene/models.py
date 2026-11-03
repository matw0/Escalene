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
    