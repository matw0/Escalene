from escalene.models import ServiceRecord


def test_service_record_uses_expected_defaults():
    service = ServiceRecord(
        name="ExampleService",
        display_name="Example Service",
    )

    assert service.binary_path is None
    assert service.collection_errors == ()