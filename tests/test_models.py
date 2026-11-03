from escalene.models import ServiceRecord


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