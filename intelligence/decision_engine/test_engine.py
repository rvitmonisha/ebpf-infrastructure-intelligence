from intelligence.decision_engine.engine import DecisionEngine


def main():
    print("Decision engine test started.")

    engine = DecisionEngine()

    high_security_result = {
        "incident_id": "INC-9100",
        "pid": 9100,
        "process_name": "nc",
        "findings": [
            "High-severity suspicious process activity detected.",
            "Abnormally high event frequency detected.",
        ],
        "event_count": 6,
    }

    decision = engine.decide(high_security_result)

    print("High-security decision:")
    print(decision)

    assert decision["action"] == "RECOMMEND"
    assert "High-severity" in decision["reason"]

    normal_result = {
        "incident_id": "INC-9101",
        "pid": 9101,
        "process_name": "bash",
        "findings": [
            "No significant root-cause indicators detected."
        ],
        "event_count": 1,
    }

    normal_decision = engine.decide(normal_result)

    print("Normal decision:")
    print(normal_decision)

    assert normal_decision["action"] == "MONITOR"

    print("Decision engine test completed successfully.")


if __name__ == "__main__":
    main()
