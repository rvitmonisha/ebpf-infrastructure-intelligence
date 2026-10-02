from intelligence.integration.recommendation_service import RecommendationService


def main():
    print("Recommendation service test started.")

    service = RecommendationService()

    decision = {
        "action": "RECOMMEND",
        "reason": "Security-related activity requires investigation.",
    }

    recommendation = service.recommend(decision)

    print("Recommendation result:")
    print(recommendation)

    assert recommendation["recommendation"] == (
        "Investigate the affected process."
    )
    assert recommendation["safe_to_automate"] is False

    print("Recommendation service test completed successfully.")


if __name__ == "__main__":
    main()
