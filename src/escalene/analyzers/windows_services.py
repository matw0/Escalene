from escalene.models import Finding, ServiceRecord, Token

def analyze_service_config(service: ServiceRecord, token: Token,) -> Finding | None:
    if service.can_change_config is not True:
        return None

    service_account = service.run_as_account or "Unavailable to retrieve"
    binary_path = service.binary_path or "Unavailable to retrieve"

    return Finding(
        finding_id="ESC-SERV-{} ~ FEATURE TO BE DEVELOPED DUE TO COMPLEXITY!",
        title="Service Configuration allows modification",
        severity="High", # We need to calculate the severity of this, rather than assuming that its high
        confidence="High", # Also something we need to calculate, just because we can change the config doesn't guarantee privilege escalation
        target=service.name,
        description=(
        "FEATURE TO BE DEVELOPED DUE TO COMPLEXITY!"
        ),
        evidence=(
            f"Current Account: {token.account_name}",
            f"Service Account: {service_account}",
            f"Binary Path: {binary_path}",
            "SERVICE_CHANGE_CONFIG: GRANTED",
        ),
        remediation=(
            "FEATURE TO BE DEVELOPED DUE TO COMPLEXITY!"
        ),
        limitations=(
            "FEATURE TO BE DEVELOPED DUE TO COMPLEXITY!",
        ),
    )