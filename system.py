from access import Record, \
    Principal, \
    RecordId, \
    Optional, \
    Action
from typing import Callable
# a system that can perform actions on our records
# using access control lists (ACLs)
Authorizer = Callable[[Principal, Action, Record], bool]


class System:
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
