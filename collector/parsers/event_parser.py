from collector.event_pipeline.event_schema import Event, EventType


class EventParser:
    def parse_process_event(
        self,
        pid: int,
        uid: int,
        timestamp_ns: int,
        process_name: str,
    ) -> Event:
        return Event(
            event_type=EventType.PROCESS,
            pid=pid,
            uid=uid,
            timestamp_ns=timestamp_ns,
            process_name=process_name,
        )

    def parse_syscall_event(
        self,
        pid: int,
        uid: int,
        timestamp_ns: int,
        process_name: str,
    ) -> Event:
        return Event(
            event_type=EventType.SYSCALL,
            pid=pid,
            uid=uid,
            timestamp_ns=timestamp_ns,
            process_name=process_name,
        )

    def parse_network_event(
        self,
        pid: int,
        uid: int,
        timestamp_ns: int,
        process_name: str,
    ) -> Event:
        return Event(
            event_type=EventType.NETWORK,
            pid=pid,
            uid=uid,
            timestamp_ns=timestamp_ns,
            process_name=process_name,
        )
