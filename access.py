from dataclasses import dataclass
from enum import Enum
from typing import TypeVar, Generic, Optional, Callable
import pytest

NoneType = type(None)
PrincipalId = int


# this sector represents the person seeking access to the system
@dataclass
class Principal:
    id: PrincipalId
    name = str


# different access control methods require different types of metadata
# attached to records(e.g ACLs, opt-in info)
RecordMetadata = TypeVar("RecordMetadata")
RecordId = int


# single parent record
@dataclass
class Record(Generic[RecordMetadata]):
    id: RecordId
    person_name: str
    dob: int
    metadata: Optional[RecordMetadata] = None


# what the said person would be able to do on a said record
class Action(Enum):
    READ = 1
    WRITE = 2


# a system that can perform actions on our records
# using access control lists (ACLs)
Authorizer = Callable[[Principal, Action, Record], bool]


class System:
    # def __init__(self):
    #     self.records = Record
    #

    def __int__(self, record: list[Record], authorizer=Authorizer, principals=Principal):
        self.records = record
        self.is_authorized = authorizer

    def get(self, record_id: RecordId, principal: Principal) -> Optional[Record]:
        # """Return a record if the principal has Action.Read access to it and
        # None if not"""
        for record in self.records:
            if record_id == record_id and self.is_authorized(principal,
                                                             Action.READ,
                                                             record):
                return record
        return None

    def update(self, record_id: RecordId, principal: Principal, updates: dict):
        """Update the record with id equal to record_id only if the
        Principal has Action.Write access. Otherwise, do nothing"""
        for record in self.records:
            if record_id == record_id and self.is_authorized(principal, Action.WRITE, Record):
                for (k, v) in updates.items():
                    setattr(record, k, v)


# set up some test data
# Members of your engineering team.
@pytest.fixture
def principals() -> tuple[Principal, Principal]:
    return Principal(1), Principal(2)


# Persons records we need to protect.
@pytest.fixture
def records() -> list[Record[NoneType]]:
    return [Record[NoneType](1, "Alyssa", 1965), Record[NoneType](2, "Ben", 1974)]


# In some cases, we are going to want metadata on our records. For example,
# ACLs will be attached to records and ABAC will allow us to use any
# attribute we want to attach to any record
def records_with_metadata(metadata: tuple[RecordMetadata, RecordMetadata]) -> list[Record[RecordMetadata]]:
    return [Record[RecordMetadata](1, "Alyssa", 1965, metadata[0]), Record[RecordMetadata](2, "Ben", 1974, metadata[1])]


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


# def test_acl(principals: tuple[Principal, Principal]):
#     @dataclass
#     class AccessControl:
#         principal: Principal
#         actions: set[Action]
#
#     (alice, bob) = principals
#     alice_rw = AccessControl(alice, {Action.READ, Action.WRITE})
#     bob_r = AccessControl(bob, {Action.READ})
#
#     # Create new records with ACLs directly attached
#     records: list[Record[list[AccessControl]]] = records_with_metadata(
#         ([alice_rw], [alice_rw, bob_r])
#     )
#
#     def acl_authorizer(
#         principal: Principal,
#         action: Action,
#         record: Record[list[AccessControl]],
#     ) -> bool:
#         from collections.abc import Iterable
#
#         if isinstance(record.metadata, Iterable):
#             for acl in record.metadata:
#                 if acl.principal.id == principal.id and action in acl.actions:
#                     return True
#         return False
#
#     # main.py::test_acl PASSED
#     authorizer_tests(acl_authorizer, records, principals)
# def test_rbac(
#         principals: tuple[Principal, Principal],
#         records: list[Record[NoneType]]
# ):
#     # The Role allows us to define relationships between many Principals and
#     # many Records in one place.
#     @dataclass
#     class Role:
#         name: str
#         principal_ids: set[PrincipalId]
#         permissions: list[tuple[set[Action], set[RecordId]]]
#
#         def has_principal(self, id: PrincipalId) -> bool:
#             return id in self.principal_ids
#
#         def has_action_for_record(
#                 self, action: Action, record_id: RecordId
#         ) -> bool:
#             for (actions, record_ids) in self.permissions:
#                 if action in actions and record_id in record_ids:
#                     return True
#             return False
#
#     # Convenience method to pull ids out of records.
#     def get_ids(records) -> set[RecordId]:
#         return set(map(lambda r: r.id, records))
#
#     (alice, bob) = principals
#     roles = [
#         Role(
#             "Admin",
#             {alice.id},
#             [({Action.READ, Action.WRITE}, get_ids(records))],
#         ),
#         Role(
#             "ReadOne",
#             {bob.id},
#             [({Action.READ}, get_ids(records[1:]))]
#         ),
#     ]
#
#     def rbac_authorizer(
#             principal: Principal, action: Action, record: Record[NoneType]
#     ) -> bool:
#         for role in roles:
#             if (role.has_principal(principal.id) and
#                     role.has_action_for_record(action, record.id)
#             ):
#                 return True
#         return False
#
#     # main.py::test_rbac PASSED
#     authorizer_tests(rbac_authorizer, records)


def test_abac(principals: tuple[Principal, Principal], records: list[Record[NoneType]]):
    import operator as op

    # Comparison operators for comparing attributes to values in our Policies
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

    # Define policies to pass our tests (even if this is not a realistic use
    # case for ABAC)
    policies = [
        Policy("Admin",
               {alice.id},
               {Action.READ, Action.WRITE},
               [Rule("Record", "id", "any")],
               ),
        Policy(
            "ReadOne",
            {bob.id},
            {Action.READ},
            [Rule("Record", "id", "=")],
        )
    ]

    # This will evaluate a policy for every record passed in. We're only
    # going to support attributes in Records to get the tests to pass.
    def abac_authorizer(principal: Principal, action: Action, record: Record[NoneType]) -> bool:
        for policy in policies:
            if policy.has_principal(principal.id) and policy.has_action(action):
                for rule in policy.rules:
                    if rule.entity_name == "Record":
                        # Evaluate the Rule by pulling the attribute from the
                        # Record and comparing it to the value in the Rule
                        record_value = getattr(record, rule.attribute_name)
                        if operators[rule.operator](record_value, rule.compare_value):
                            return True
        return False

    # main.py::test_abac PASSED
    authorizer_tests(abac_authorizer, records, principals)
