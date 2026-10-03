import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from collector.parsers.ebpf_output_parser import EBPFOutputParser
from correlation.integration.incident_service import IncidentService
from security.detection_engine.detector import SecurityDetector
from intelligence.anomaly_detection.detector import AnomalyDetector
from intelligence.integration.incident_intelligence_service import (
    IncidentIntelligenceService,
)


HOST = "0.0.0.0"
PORT = 8000

metrics = {
    "ebpf_events_total": 0,
    "ebpf_process_events_total": 0,
    "ebpf_syscall_events_total": 0,
    "ebpf_network_events_total": 0,
    "ebpf_security_alerts_total": 0,
    "ebpf_anomalies_total": 0,
    "ebpf_incidents_total": 0,
    "ebpf_recommendations_total": 0,
}

lock = threading.Lock()


def increment(metric_name):
    with lock:
        metrics[metric_name] += 1


def collect_ebpf_events():
    command = [
        "sudo",
        "-n",
        "./ebpf/process/process_monitor",
    ]

    parser = EBPFOutputParser()
    incident_service = IncidentService()

    intelligence_service = IncidentIntelligenceService(
        security_detector=SecurityDetector(),
        anomaly_detector=AnomalyDetector(threshold=5),
    )

    while True:
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            print(
                "Connected to eBPF process monitor.",
                flush=True,
            )

            if process.stdout is None:
                continue

            for line in process.stdout:
                line = line.strip()

                if not line:
                    continue

                event = parser.parse_process_output(line)

                if event is None:
                    continue

                increment("ebpf_events_total")
                increment("ebpf_process_events_total")

                incident_service.add_event(event)

                incident = incident_service.build_incident(
                    event.pid
                )

                if incident is None:
                    continue

                result = intelligence_service.analyze_incident(
                    incident
                )

                increment("ebpf_incidents_total")

                findings = result["analysis"]["findings"]

                if (
                    "High-severity suspicious process activity detected."
                    in findings
                    or
                    "Security-related activity detected."
                    in findings
                ):
                    increment("ebpf_security_alerts_total")

                if (
                    "Abnormally high event frequency detected."
                    in findings
                ):
                    increment("ebpf_anomalies_total")

                if result["decision"]["action"] == "RECOMMEND":
                    increment("ebpf_recommendations_total")

                print(
                    f"Live intelligence | "
                    f"PID: {event.pid} | "
                    f"Process: {event.process_name} | "
                    f"Decision: "
                    f"{result['decision']['action']}",
                    flush=True,
                )

            process.wait()

        except Exception as error:
            print(
                f"Collector error: {error}",
                flush=True,
            )

        print(
            "eBPF collector stopped. Restarting...",
            flush=True,
        )


class MetricsHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        if self.path == "/metrics":

            with lock:
                current_metrics = dict(metrics)

            metric_info = {
                "ebpf_events_total":
                    "Total number of eBPF events processed.",
                "ebpf_process_events_total":
                    "Total number of process events detected.",
                "ebpf_syscall_events_total":
                    "Total number of syscall events detected.",
                "ebpf_network_events_total":
                    "Total number of network events detected.",
                "ebpf_security_alerts_total":
                    "Total number of security alerts generated.",
                "ebpf_anomalies_total":
                    "Total number of anomalies detected.",
                "ebpf_incidents_total":
                    "Total number of incidents analyzed.",
                "ebpf_recommendations_total":
                    "Total number of recommendations generated.",
            }

            output = []

            for name, value in current_metrics.items():

                output.append(
                    f"# HELP {name} {metric_info[name]}"
                )

                output.append(
                    f"# TYPE {name} counter"
                )

                output.append(
                    f"{name} {value}"
                )

                output.append("")

            data = "\n".join(output)

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "text/plain; version=0.0.4",
            )

            self.send_header(
                "Content-Length",
                str(len(data.encode("utf-8"))),
            )

            self.end_headers()

            self.wfile.write(
                data.encode("utf-8")
            )

        elif self.path == "/health":

            data = "OK\n"

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "text/plain",
            )

            self.end_headers()

            self.wfile.write(
                data.encode("utf-8")
            )

        else:

            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        return


def start_metrics_server():

    server = HTTPServer(
        (HOST, PORT),
        MetricsHandler,
    )

    print(
        "Metrics server running on "
        "http://0.0.0.0:8000/metrics",
        flush=True,
    )

    server.serve_forever()


def main():

    metrics_thread = threading.Thread(
        target=start_metrics_server,
        daemon=True,
    )

    metrics_thread.start()

    collect_ebpf_events()


if __name__ == "__main__":
    main()
