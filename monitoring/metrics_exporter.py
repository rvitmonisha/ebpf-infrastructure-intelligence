#!/usr/bin/env python3
"""Prometheus exporter for eBPF Infrastructure Intelligence."""

import logging
import os
import subprocess
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from collector.parsers.ebpf_output_parser import EBPFOutputParser
from correlation.integration.incident_service import IncidentService
from intelligence.anomaly_detection.detector import AnomalyDetector
from intelligence.integration.incident_intelligence_service import (
    IncidentIntelligenceService,
)
from security.detection_engine.detector import SecurityDetector

HOST = os.getenv("METRICS_HOST", "0.0.0.0")
PORT = int(os.getenv("METRICS_PORT", "8000"))
COLLECTOR_ENABLED = os.getenv(
    "EBPF_COLLECTOR_ENABLED", "false"
).strip().lower() not in {"0", "false", "no", "off"}

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
MONITOR_BINARY = os.path.join(
    PROJECT_ROOT, "ebpf", "process", "process_monitor"
)
RESTART_DELAY = 5

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("ebpf_metrics_exporter")

LOCK = threading.Lock()
METRICS = {
    "ebpf_exporter_up": 1,
    "ebpf_events_total": 0,
    "ebpf_collector_running": 0,
    "ebpf_collector_errors_total": 0,
    "ebpf_last_event_timestamp_seconds": 0,
    "ebpf_security_alerts_total": 0,
    "ebpf_behavior_alerts_total": 0,
    "ebpf_anomalies_total": 0,
    "ebpf_incidents_analyzed_total": 0,
    "ebpf_recommendations_total": 0,
}
HELP = {
    "ebpf_exporter_up": "Whether the metrics exporter is running.",
    "ebpf_events_total": "Total valid eBPF events parsed.",
    "ebpf_collector_running": "Whether the eBPF collector is running.",
    "ebpf_collector_errors_total": "Total collector errors.",
    "ebpf_last_event_timestamp_seconds": "Unix time of the last parsed event.",
    "ebpf_security_alerts_total": "Security alerts emitted during event processing.",
    "ebpf_behavior_alerts_total": "Behavioral alerts emitted during event processing.",
    "ebpf_anomalies_total": "Anomaly alerts emitted during event processing.",
    "ebpf_incidents_analyzed_total": "Process incidents analyzed.",
    "ebpf_recommendations_total": "Incident analyses recommending investigation.",
}
COUNTERS = set(METRICS) - {
    "ebpf_exporter_up",
    "ebpf_collector_running",
    "ebpf_last_event_timestamp_seconds",
}


def increment(name, amount=1):
    with LOCK:
        METRICS[name] += amount


def set_value(name, value):
    with LOCK:
        METRICS[name] = value


def render_metrics():
    with LOCK:
        snapshot = dict(METRICS)
    lines = []
    for name, value in snapshot.items():
        kind = "counter" if name in COUNTERS else "gauge"
        lines.extend((
            f"# HELP {name} {HELP[name]}",
            f"# TYPE {name} {kind}",
            f"{name} {value}",
        ))
    return "\n".join(lines) + "\n"


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            status, content_type = 200, "application/json"
            body = b'{"status":"ok"}\n'
        elif self.path == "/metrics":
            status = 200
            content_type = "text/plain; version=0.0.4; charset=utf-8"
            body = render_metrics().encode()
        else:
            status, content_type = 404, "application/json"
            body = b'{"error":"not found"}\n'

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        logger.debug("%s - %s", self.address_string(), fmt % args)


def start_metrics_server():
    server = ThreadingHTTPServer((HOST, PORT), MetricsHandler)
    logger.info("Metrics server listening on %s:%s", HOST, PORT)
    server.serve_forever()


def build_monitor_command():
    if os.geteuid() == 0:
        return [MONITOR_BINARY]
    return ["sudo", "-n", MONITOR_BINARY]


def process_event(line, parser, incident_service, security_detector,
                  anomaly_detector, intelligence_service, seen_pids):
    """Parse one real monitor line and update the project's detectors."""
    event = parser.parse_process_output(line)
    if event is None:
        logger.debug("Ignoring unrecognized monitor output: %s", line.strip())
        return

    increment("ebpf_events_total")
    set_value("ebpf_last_event_timestamp_seconds", time.time())
    incident_service.add_event(event)

    security_alert = security_detector.analyze_event(event)
    anomaly_alert = anomaly_detector.analyze_event(event)

    if security_alert:
        if security_alert.get("type") == "REPEATED_PROCESS_EXECUTION":
            increment("ebpf_behavior_alerts_total")
            logger.warning("Behavior alert: %s", security_alert)
        else:
            increment("ebpf_security_alerts_total")
            logger.warning("Security alert: %s", security_alert)

    if anomaly_alert:
        increment("ebpf_anomalies_total")
        logger.warning("Anomaly alert: %s", anomaly_alert)

    # Analyze each PID once for the lifetime of this collector process.
    # IncidentService retains the events correlated to that PID.
    if event.pid not in seen_pids:
        seen_pids.add(event.pid)
        incident = incident_service.build_incident(event.pid)
        if incident is not None:
            try:
                result = intelligence_service.analyze_incident(incident)
                increment("ebpf_incidents_analyzed_total")
                decision = result.get("decision", {})
                if decision.get("action") == "RECOMMEND":
                    increment("ebpf_recommendations_total")
                logger.info(
                    "Incident analysis for PID %s: %s", event.pid, result
                )
            except Exception:
                logger.exception("Incident analysis failed for PID %s", event.pid)


def collect_ebpf_events():
    if not os.path.isfile(MONITOR_BINARY):
        raise FileNotFoundError(f"Monitor binary not found: {MONITOR_BINARY}")
    if not os.access(MONITOR_BINARY, os.X_OK):
        raise PermissionError(f"Monitor is not executable: {MONITOR_BINARY}")

    parser = EBPFOutputParser()
    incident_service = IncidentService()
    security_detector = SecurityDetector()
    anomaly_detector = AnomalyDetector(threshold=5, window_seconds=10)
    intelligence_service = IncidentIntelligenceService(
        security_detector=security_detector,
        anomaly_detector=anomaly_detector,
    )
    seen_pids = set()

    command = build_monitor_command()
    logger.info("Starting eBPF monitor: %s", command)

    with subprocess.Popen(
        command,
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    ) as process:
        set_value("ebpf_collector_running", 1)
        try:
            if process.stdout is not None:
                for line in process.stdout:
                    process_event(
                        line, parser, incident_service, security_detector,
                        anomaly_detector, intelligence_service, seen_pids,
                    )
            return_code = process.wait()
            if return_code:
                raise RuntimeError(
                    f"eBPF monitor exited with status {return_code}"
                )
        finally:
            set_value("ebpf_collector_running", 0)


def collector_loop():
    while True:
        try:
            collect_ebpf_events()
            logger.warning("Collector stopped; retrying in %s seconds", RESTART_DELAY)
        except Exception:
            increment("ebpf_collector_errors_total")
            logger.exception("eBPF collector failed")
        time.sleep(RESTART_DELAY)


def main():
    server = threading.Thread(
        target=start_metrics_server, name="metrics-server", daemon=True
    )
    server.start()

    if not COLLECTOR_ENABLED:
        logger.info("Collector disabled; serving metrics and health endpoints.")
        server.join()
    else:
        collector_loop()


if __name__ == "__main__":
    main()
