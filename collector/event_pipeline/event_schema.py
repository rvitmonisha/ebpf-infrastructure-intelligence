from dataclasses import dataclass
from enum import Enum


class EventType(Enum):
    PROCESS = "process"
    SYSCALL = "syscall"
    NETWORK = "network"


@dataclass
class Event:
    event_type: EventType
    pid: int
    uid: int
    timestamp_ns: int
    process_name: str

    def to_dict(self):
        return {
            "event_type": self.event_type.value,
            "pid": self.pid,
            "uid": self.uid,
            "timestamp_ns": self.timestamp_ns,
            "process_name": self.process_name,
        }
