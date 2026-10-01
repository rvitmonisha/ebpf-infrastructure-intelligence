from intelligence.decision_engine.engine import DecisionEngine


def main():
    engine = DecisionEngine()

    print("Decision engine test started.")

    security_case = {
        "incident_id": "INC-7001",
        "pid": 7001,
        "process_name": "suspicious-process",
        "findings": [
            "Security-related activity detected.",
        ],
        "event_count": 5,
    }

    anomaly_case = {
        "incident_id": "INC-7002",
        "pid": 7002,
        "process_name": "busy-process",
        "findings": [
            "Abnormally high event frequency detected.",
        ],
        "event_count": 10,
    }

    normal_case = {
        "incident_id": "INC-7003",
        "pid": 7003,
        "process_name": "normal-process",
        "findings": [],
        "event_count": 2,
    }

    print("Security case:")
    print(engine.decide(security_case))

    print("Anomaly case:")
    print(engine.decide(anomaly_case))

    print("Normal case:")
    print(engine.decide(normal_case))

    print("Decision engine test completed successfully.")


if __name__ == "__main__":
    main()
