import json
from datetime import datetime, timezone
from pathlib import Path


class IncidentReporter:
    def __init__(self, output_dir="reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, events, alerts, analyses):
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_events": len(events),
                "unique_processes": len({event.pid for event in events}),
                "total_alerts": len(alerts),
                "high_severity_alerts": sum(
                    1 for alert in alerts
                    if alert.get("severity") == "HIGH"
                ),
            },
            "events": [event.to_dict() for event in events],
            "alerts": alerts,
            "incident_analyses": analyses,
        }

        output_path = self.output_dir / "latest_incident_report.json"
        output_path.write_text(
            json.dumps(report, indent=2, default=str) + "\n",
            encoding="utf-8",
        )

        print("\n========== INCIDENT REPORT ==========")
        print(json.dumps(report["summary"], indent=2))
        print(f"Report saved to: {output_path.resolve()}")

        for alert in alerts:
            print(
                f"[{alert.get('severity', 'UNKNOWN')}] "
                f"{alert.get('type', 'ALERT')} | "
                f"PID {alert.get('pid', 'N/A')} | "
                f"{alert.get('process_name', 'unknown')}"
            )

        if not alerts:
            print("No security alerts were generated for these events.")

        return report
