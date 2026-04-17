from src.indicators import ALL_INDICATORS
from src.knowledge_base import THRESHOLDS


def _classify(score: int) -> str:
    if score < THRESHOLDS["legitimate"]:
        return "legitimate"
    if score < THRESHOLDS["suspicious"]:
        return "suspicious"
    return "phishing"


def analyze_message(message: dict) -> dict:
    triggered = []
    for check in ALL_INDICATORS:
        result = check(message)
        if result is not None:
            triggered.append(result)

    score = sum(r["weight"] for r in triggered)

    return {
        "id": message["id"],
        "channel": message["channel"],
        "classification": _classify(score),
        "risk_score": score,
        "triggered_indicators": triggered,
    }


def analyze_messages(data: dict) -> dict:
    results = [analyze_message(m) for m in data["messages"]]

    counts = {"legitimate": 0, "suspicious": 0, "phishing": 0}
    for r in results:
        counts[r["classification"]] += 1

    highest = max((r["risk_score"] for r in results), default=0)

    return {
        "summary": {
            "total_messages": len(results),
            "legitimate_messages": counts["legitimate"],
            "suspicious_messages": counts["suspicious"],
            "phishing_messages": counts["phishing"],
            "highest_risk_score": highest,
        },
        "results": results,
    }
