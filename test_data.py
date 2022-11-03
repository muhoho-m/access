import pytest
from access import Principal, Record, RecordMetadata
from system import Authorizer, System
NoneType = type(None)

# set up some test data


# Members of your engineering team.
@pytest.fixture
def principals() -> tuple[Principal, Principal]:
    return (Principal(1, "Alice"), Principal(2, "Bob"))


# Patient records we need to protect.
@pytest.fixture
def records() -> list[Record[NoneType]]:
    return [
        Record[NoneType](1, "Alyssa", 1965),
        Record[NoneType](2, "Ben", 1974),
    ]


# In some cases, we are going to want metadata on our records. For example,
# ACLs will be attached to records and ABAC will allow us to use any
# attribute we want to attach to any record
def records_with_metadata(
        metadata: tuple[RecordMetadata, RecordMetadata]
) -> list[Record[RecordMetadata]]:
    return [
        Record[RecordMetadata](1, "Alyssa", 1965, metadata[0]),
        Record[RecordMetadata](2, "Ben", 1974, metadata[1]),
    ]


def authorizer_tests(authorized: Authorizer, records: list[Record], principals: principals):
    """Asserts that:
    1. Alice gets Read and Write access to both records.
    2. Bob gets read permission to Ben's record"""
    system = System()
    # system = System(records, authorized, principals)

    assert records[0] == system.get(records[0].id, "Alice")
    assert not system.get(records[0].id, "Bob")
    assert records[1] == system.get(records[1].id, "Bob")

    system.update(records[0].id, "bob", {"dob": 1994})
    assert 1994 == system.get(records[0].id, "Alice").dob

    system.update(records[1].id, "Bob", {"dob": 2006})
    assert 1974 == system.get(records[1].id, "Bob").dob
