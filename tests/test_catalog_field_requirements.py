"""Regression tests for DEI detection field-readiness metadata."""

from library_helpers import load_catalog


def test_every_detection_defines_required_fields_for_required_sources() -> None:
    catalog = load_catalog()
    assert catalog

    for detection in catalog:
        required_sources = detection["required_sources"]
        required_fields = detection.get("required_fields")
        assert isinstance(required_fields, dict), detection["id"]
        assert set(required_fields) == set(required_sources), detection["id"]
        for source in required_sources:
            groups = required_fields[source]
            assert groups, (detection["id"], source)
            for group in groups:
                assert isinstance(group, list) and group, (detection["id"], source)
                assert all(isinstance(field, str) and field.strip() for field in group)
