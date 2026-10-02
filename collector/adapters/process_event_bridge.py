from collector.adapters.process_adapter import ProcessAdapter
from collector.event_pipeline.event_collector import EventCollector
from collector.event_pipeline.pipeline import EventPipeline
from collector.parsers.ebpf_output_parser import EBPFOutputParser
from correlation.integration.correlation_service import CorrelationService


class ProcessEventBridge:
    def __init__(self):
        self.adapter = ProcessAdapter()
        self.parser = EBPFOutputParser()

        self.pipeline = EventPipeline()
        self.collector = EventCollector(self.pipeline)
        self.correlation_service = CorrelationService()

    def run(self, max_events: int = 5):
        processed_events = 0

        for line in self.adapter.stream_events():
            event = self.parser.parse_process_output(line)

            if event is None:
                continue

            self.collector.collect(event)
            self.correlation_service.process_event(event)

            processed_events += 1

            print(
                f"Event ingested: {event.to_dict()}",
                flush=True,
            )

            if processed_events >= max_events:
                break

        return processed_events
