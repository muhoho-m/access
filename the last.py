from dataclasses import dataclass
from enum import Enum
from typing import TypeVar, Generic, Optional, Callable
import pytest
import operator as op

NoneType = type(None)
PrincipalId = int


# define the person seeking access to some records
@dataclass
class Principal:
    id = PrincipalId
    name = str


# define the data to be used in different control methods
RecordMetadata = TypeVar("RecordMetadata")
RecordId = int


# define the records
@dataclass
class Record(Generic[RecordMetadata]):
    id: RecordId
    person_name: str
    dob: int
    metadata: Optional[RecordMetadata] = None


# actions a person can do to the data
class Action(Enum):
    READ = 1
    WRITE = 2


# define the system to be used in accessing the data
Authorizer = Callable[[Principal, Action, Record], bool]


class System:

    def __init__(self, records: list[Record], authorizer: Authorizer):
        self.records = records
        self.is_authorized = authorizer

    # function to get records
    def get(self, record_id: RecordId, principal: Principal) -> Optional[Record]:
        """return a record if the principals has Action.Read access
        anf none if not"""
        for record in self.records:
            if record_id == record_id and self.is_authorized(principal, Action.READ, record):
                return record
        return None

    # function to update records
    def update(self, record_id: RecordId, principal: Principal, updates: dict):
        """update a record with equal to record_id only if the principal has
        Action.Write access otherwise don't."""
        for record in self.records:
            if record_id == record_id and self.is_authorized(principal, Action.WRITE, record):
                for (k, v) in updates.items():
                    setattr(record, k, v)


# some test data
@pytest.fixture
def principals() -> tuple[Principal, Principal]:
    return Principal(), Principal()
    # return Principal(1, "Alice"), Principal(2, "Bob")


# persons records we are protecting
@pytest.fixture
def records() -> list[Record[NoneType]]:
    return [Record[NoneType](1, "Alyssa", 1965), Record[NoneType](2, "Ben", 1974)]


def records_with_metadata(metadata: tuple[RecordMetadata, RecordMetadata]) -> list[Record[RecordMetadata]]:
    return [Record[RecordMetadata](1, "Alyssa", 1965, metadata[0]), Record[RecordMetadata](2, "Ben", 1974, metadata[1])]


def authorizer_tests(authorized: Authorizer, records: list[Record]):
    """Asserts that:
    1. Alice gets read and write to both records
    2. Bob gets read permission to Ben's record
    """
    # initialize our system

    system = System(records, authorized)

    assert records[0] == system.get(records[0].id, "Alice")
    assert not system.get(records[0].id, "Bob")
    assert records[1] == system.get(records[1].id, "Bob")

    system.update(records[0].id, "bob", {"dob": 1994})
    assert 1994 == system.get(records[0].id, "Alice").dob

    system.update(records[1].id, "Bob", {"dob": 2006})
    assert 1974 == system.get(records[1].id, "Bob").dob


# the attribute based access control to the data
def test_abac(principals: tuple[Principal, Principal], records: list[Record[NoneType]]):
    # define comparison operators for comparing attributes to values in our policies
    operators = {
        "=": op.eq,
        "!=": op.ne,
        "any": lambda _1, _2: True,
        "true": lambda x, _: bool(x),
        "false": lambda x, _: not x,
    }

    # A Rule holds the information required to look up an attribute in the
    # right entity and compare it to a given value. An example of a rule
    # could be "RecordAttributes.email_opt_out = True" to represent a record
    # related to a user who has opted out of email correspondence.
    @dataclass
    class Rule:
        entity_name: str
        attribute_name: str
        operator: str
        compare_value: Optional = None

    # Policy has Principals and Actions but not Records. Whether a Principal
    # has access to a given record is determined by the conditions defined
    # in the Rules
    @dataclass
    class Policy:
        name: str
        principal_ids: set[PrincipalId]
        actions: set[Action]
        rules: list[Rule]

        def has_principal(self, id: PrincipalId) -> bool:
            return id in self.principal_ids

        def has_action(self, action: Action) -> bool:
            return action in self.actions

    (alice, bob) = principals

    # Define policies to pass our tests (even if
    # this is not a realistic use case for ABAC)
    policies = [
        Policy(
            "Admin",
            {alice.id},
            {Action.READ, Action.WRITE},
            [Rule("Record", "id", "any")]
        ),
        Policy(
            "ReadOne",
            {bob.id},
            {Action.READ},
            [Rule("Record", "id", "any")]
        )
    ]

    # This will evaluate a policy for every record passed in. We're only
    # going to support attributes in Records to get the tests to pass.
    def abac_authorizer(principal: Principal, action: Action, record: Record[NoneType]) -> bool:
        for policy in policies:
            if policy.has_principal(1) or policy.has_principal(2) and policy.has_action(action):
                for rule in policy.rules:
                    if rule.entity_name == "Record":
                        # Evaluate the Rule by pulling the attribute from the
                        # Record and comparing it to the value in the Rule
                        record_value = getattr(record, rule.attribute_name)
                        if operators[rule.operator](record_value, rule.compare_value):
                            return True
        return False

    authorizer_tests(abac_authorizer, records)
