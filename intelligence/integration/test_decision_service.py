from intelligence.integration.decision_service import DecisionService


def main():
    print("Decision service test started.")

    service = DecisionService()

    analysis_result = {
        "incident_id": "INC-7001",
        "pid": 7001,
        "process_name": "test-process",
        "findings": [
            "Security-related activity detected."
        ],
        "event_count": 3,
    }

    decision = service.decide(analysis_result)

    print("Decision result:")
    print(decision)

    assert decision["action"] == "RECOMMEND"
    assert "Security" in decision["reason"]

    print("Decision service test completed successfully.")


if __name__ == "__main__":
    main()
