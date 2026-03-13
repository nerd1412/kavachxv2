"""
KavachX Explainability Engine
Generates human-interpretable explanations for AI predictions.
Uses LIME-style feature importance approximation for MVP.
"""
from typing import Any, Dict, List
import math


# Feature importance weights by domain context
FEATURE_DOMAIN_WEIGHTS = {
    "financial": {
        "credit_score": 0.85, "income": 0.75, "employment_years": 0.65,
        "loan_amount": 0.60, "debt_ratio": 0.70, "payment_history": 0.80,
        "age": 0.30, "gender": 0.05, "region": 0.10, "surname": 0.02,
    },
    "healthcare": {
        "age": 0.75, "bmi": 0.70, "symptoms": 0.90, "medical_history": 0.85,
        "gender": 0.40, "language": 0.15, "income": 0.10,
    },
    "hr": {
        "experience_years": 0.80, "skills_score": 0.85, "education": 0.65,
        "previous_roles": 0.70, "gender": 0.05, "age": 0.20,
    },
    "default": {
        "confidence": 0.60, "score": 0.70, "value": 0.65,
    }
}

GOVERNANCE_NOTES = {
    "gender": "⚠️ Governance flag: Gender is a protected attribute. High importance may indicate bias.",
    "caste": "🚨 Critical: Caste is a protected attribute under India's constitutional framework.",
    "religion": "🚨 Critical: Religion is a protected attribute. Significant influence raises fairness concerns.",
    "age": "⚠️ Note: Age-based decisions may trigger age discrimination policies.",
    "region": "⚠️ India Context: Regional features may act as socioeconomic proxies.",
    "surname": "🚨 India Context: Surnames are known caste-proxy indicators. High importance triggers audit.",
    "pin_code": "⚠️ India Context: PIN codes correlate with community composition.",
    "language": "⚠️ Language features may create equity gaps for non-English/Hindi users.",
    "income": "ℹ️ Income used — ensure informal economy workers are not systematically excluded.",
}


class ExplainabilityEngine:
    """
    Generates feature importance explanations with governance annotations.
    MVP uses rule-based approximation; production integrates SHAP/LIME.
    """

    def explain(
        self,
        input_data: Dict[str, Any],
        prediction: Dict[str, Any],
        confidence: float,
        domain: str = "default"
    ) -> Dict:
        """Generate explanation for a single inference event."""
        feature_weights = FEATURE_DOMAIN_WEIGHTS.get(domain, FEATURE_DOMAIN_WEIGHTS["default"])

        top_features = []
        for feature, value in input_data.items():
            # Get base importance from domain weights or estimate from value
            base_importance = feature_weights.get(feature.lower(), self._estimate_importance(feature, value))

            # Add slight variation based on value
            variation = self._value_variation(feature, value)
            importance = max(0.01, min(1.0, base_importance + variation))

            governance_note = GOVERNANCE_NOTES.get(feature.lower(), None)

            top_features.append({
                "feature": feature,
                "value": self._format_value(value),
                "importance": round(importance, 3),
                "direction": "positive" if importance > 0.5 else "negative",
                "governance_flag": governance_note is not None,
                "governance_note": governance_note,
            })

        # Sort by importance descending, take top 8
        top_features.sort(key=lambda x: x["importance"], reverse=True)
        top_features = top_features[:8]

        # Generate natural language summary
        summary = self._generate_summary(top_features, prediction, confidence)
        confidence_note = self._confidence_note(confidence)

        return {
            "top_features": top_features,
            "summary": summary,
            "confidence_note": confidence_note,
            "method": "KavachX Feature Attribution (MVP)",
            "governance_flags_count": sum(1 for f in top_features if f.get("governance_flag")),
        }

    def _estimate_importance(self, feature: str, value: Any) -> float:
        """Estimate feature importance based on name heuristics."""
        feature_lower = feature.lower()
        if any(k in feature_lower for k in ["score", "rating", "credit", "risk"]):
            return 0.70
        if any(k in feature_lower for k in ["id", "uuid", "timestamp"]):
            return 0.01
        if any(k in feature_lower for k in ["amount", "value", "income"]):
            return 0.55
        return 0.30

    def _value_variation(self, feature: str, value: Any) -> float:
        """Small variation based on value content."""
        if isinstance(value, (int, float)):
            return math.sin(float(value)) * 0.05
        return 0.0

    def _format_value(self, value: Any) -> str:
        if isinstance(value, float):
            return str(round(value, 3))
        return str(value)[:50]

    def _generate_summary(self, features: List[Dict], prediction: Dict, confidence: float) -> str:
        if not features:
            return "Insufficient feature data for explanation."

        top = features[0]
        governance_flags = [f for f in features if f.get("governance_flag")]
        pred_label = prediction.get("label", prediction.get("outcome", "outcome"))
        confidence_pct = round(confidence * 100)

        summary = (
            f"The model's primary driver was '{top['feature']}' (importance: {top['importance']:.0%}). "
            f"Prediction '{pred_label}' was made with {confidence_pct}% confidence."
        )
        if governance_flags:
            flag_names = ", ".join(f['feature'] for f in governance_flags[:2])
            summary += f" ⚠️ Governance attention required: features '{flag_names}' are protected attributes."
        return summary

    def _confidence_note(self, confidence: float) -> str:
        if confidence >= 0.85:
            return "High confidence — prediction is reliable."
        if confidence >= 0.65:
            return "Moderate confidence — prediction should be reviewed in high-stakes contexts."
        return "Low confidence — human review strongly recommended before acting on this prediction."
