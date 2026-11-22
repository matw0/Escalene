from escalene.models import Finding, ServiceRecord, Token

def analyze_service_config(service: ServiceRecord, token: Token, FID_count: int,) -> Finding | None:
    if service.can_change_config is not True:
        return None

    service_account = service.run_as_account or "Unavailable to retrieve"
    binary_path = service.binary_path or "Unavailable to retrieve"
    

    return Finding(
        finding_id=f"ESC-SERV-{FID_count:04d}",
        title="Service Configuration allows modification",
        severity="Unassessed", # We need to calculate the severity of this, rather than assuming that its high
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

def analyze_services(services: tuple[ServiceRecord, ...], token: Token,) -> tuple[Finding, ...]:
    findings = []
    for service in services:
        FID_count = len(findings) + 1

        finding = analyze_service_config(service=service, token=token, FID_count=FID_count)
        if finding is not None:
            findings.append(finding)

    return tuple(findings)