from escalene.models import ServiceRecord, Finding, Token

def test_service_record_uses_expected_defaults():
    service = ServiceRecord(
        name="ExampleService",
        display_name="Example Service",
    )

    assert service.binary_path is None
    assert service.start_type is None
    assert service.run_as_account is None
    assert service.state is None
    assert service.can_change_config is None
    assert service.collection_errors == ()


def test_finding_uses_expected_defaults():
    finding = Finding(
        finding_id="ESC-SVC-001",
        title="Service configuration can be modified",
        severity="high",
        confidence="high",
        target="ExampleService",
        description=(
            "The current effective token can obtain "
            "SERVICE_CHANGE_CONFIG access."
        ),
        evidence=(
            "Service account: LocalSystem",
            "SERVICE_CHANGE_CONFIG: granted",
        ),
        remediation=(
            "Restrict the service security descriptor so unprivileged "
            "users cannot modify its configuration."
        ),
    )

    assert finding.cwe_id is None
    assert finding.limitations == ()


def test_token_context_uses_expected_defaults():
    token = Token(account_name="EXAMPLE\\matw0")

    assert token.account_name == "EXAMPLE\\matw0"
    assert token.user_SID is None
    assert token.is_elevated is None
    assert token.integrity_level is None
    assert token.is_local_admin is None
    assert token.collection_errors == ()