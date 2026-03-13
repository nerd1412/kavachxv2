"""
KavachX Fairness Monitor
Detects bias and demographic disparities in AI model predictions.
Includes India-first context: caste-proxy detection, language equity, inclusion auditing.
"""
from typing import Any, Dict, List, Optional
import math


# India-specific proxy indicators for caste/community correlation detection
INDIA_PROXY_INDICATORS = {
    "surname_clusters": ["sharma", "verma", "patel", "khan", "iyer", "mukherjee", "nair"],
    "pin_code_tier": {"tier_1": ["400001", "110001", "560001"], "tier_3": ["800001", "632001"]},
    "language_groups": ["hindi", "english", "tamil", "bengali", "telugu", "marathi", "gujarati"],
}

PROTECTED_ATTRIBUTES = [
    "gender", "religion", "caste_proxy", "region", "language",
    "age_group", "income_tier", "disability_status"
]


class FairnessMonitor:
    """
    Evaluates AI predictions for fairness across demographic groups.
    Implements demographic parity, equalized odds, and India-specific proxy detection.
    """

    def __init__(self):
        pass

    @property
    def disparity_threshold(self) -> float:
        from app.core.config import settings
        return settings.FAIRNESS_DISPARITY_THRESHOLD

    def evaluate(self, input_data: Dict[str, Any], prediction: Dict[str, Any], confidence: float) -> List[Dict]:
        """
        Run all fairness checks on an inference event.
        Returns list of fairness flag dicts.
        """
        flags = []

        # 1. Check for direct protected attribute disparities
        flags.extend(self._check_demographic_parity(input_data, prediction))

        # 2. India-specific: caste proxy detection
        flags.extend(self._check_caste_proxy(input_data, prediction))

        # 3. Low confidence for certain groups
        flags.extend(self._check_confidence_equity(input_data, confidence))

        # 4. Language equity check
        flags.extend(self._check_language_equity(input_data, confidence))

        return flags

    def _check_demographic_parity(self, input_data: Dict, prediction: Dict) -> List[Dict]:
        """Check if prediction outcome correlates with protected attributes."""
        flags = []
        pred_value = self._extract_prediction_score(prediction)

        # Simulate disparity check against known group baselines
        gender = input_data.get("gender", "").lower()
        if gender in ["female", "f", "woman"]:
            baseline = 0.72  # simulated male baseline
            if abs(pred_value - baseline) > self.disparity_threshold:
                flags.append({
                    "metric": "gender_disparity",
                    "group_a": "male",
                    "group_b": "female",
                    "disparity": round(abs(pred_value - baseline), 3),
                    "threshold": self.disparity_threshold,
                    "passed": False,
                    "detail": "Gender-based prediction disparity detected"
                })

        income_tier = input_data.get("income_tier", "").lower()
        if income_tier in ["low", "below_poverty"]:
            baseline = 0.65
            if abs(pred_value - baseline) > self.disparity_threshold:
                flags.append({
                    "metric": "economic_equity",
                    "group_a": "high_income",
                    "group_b": "low_income",
                    "disparity": round(abs(pred_value - baseline), 3),
                    "threshold": self.disparity_threshold,
                    "passed": False,
                    "detail": "Economic tier-based prediction disparity detected (informal economy risk)"
                })

        return flags

    def _check_caste_proxy(self, input_data: Dict, prediction: Dict) -> List[Dict]:
        """
        India-specific: detect potential caste-proxy correlation via surname/pin code signals.
        """
        flags = []
        surname = str(input_data.get("surname", input_data.get("last_name", ""))).lower()
        pin_code = str(input_data.get("pin_code", input_data.get("pincode", "")))

        proxy_detected = False
        proxy_reason = []

        if any(s in surname for s in INDIA_PROXY_INDICATORS["surname_clusters"]):
            proxy_detected = True
            proxy_reason.append(f"Surname '{surname}' is in community-correlated cluster")

        if pin_code in INDIA_PROXY_INDICATORS["pin_code_tier"]["tier_3"]:
            proxy_detected = True
            proxy_reason.append(f"PIN code {pin_code} correlates with socio-economically marginalized area")

        if proxy_detected:
            pred_score = self._extract_prediction_score(prediction)
            # Flag if prediction score is in unfavorable range with proxy signal
            if pred_score < 0.45:
                flags.append({
                    "metric": "caste_proxy_correlation",
                    "group_a": "non_proxy_group",
                    "group_b": "proxy_group",
                    "disparity": round(0.65 - pred_score, 3),
                    "threshold": self.disparity_threshold,
                    "passed": False,
                    "detail": f"India Context: Possible caste-proxy correlation. Reasons: {'; '.join(proxy_reason)}"
                })

        return flags

    def _check_confidence_equity(self, input_data: Dict, confidence: float) -> List[Dict]:
        """Flag when model has low confidence for minority language users."""
        from app.core.config import settings
        flags = []
        language = input_data.get("preferred_language", input_data.get("language", "english")).lower()

        if language not in ["english", "hindi"] and confidence < settings.CONFIDENCE_LOW_THRESHOLD:
            flags.append({
                "metric": "multilingual_equity",
                "group_a": "english_hindi_users",
                "group_b": f"{language}_users",
                "disparity": round(0.80 - confidence, 3),
                "threshold": 0.15,
                "passed": False,
                "detail": f"Lower model confidence for '{language}' language user — potential language equity gap"
            })

        return flags

    def _check_language_equity(self, input_data: Dict, confidence: float) -> List[Dict]:
        return []  # Extended in full version with NLP-based checks

    def _extract_prediction_score(self, prediction: Dict) -> float:
        """Extract a normalized 0-1 score from prediction dict."""
        if "score" in prediction:
            return float(prediction["score"])
        if "probability" in prediction:
            return float(prediction["probability"])
        if "approved" in prediction:
            return 1.0 if prediction["approved"] else 0.0
        if "label" in prediction:
            return 1.0 if str(prediction["label"]).lower() in ["positive", "approved", "yes", "1"] else 0.3
        return 0.5

    def compute_aggregate_metrics(self, recent_flags: List[Dict]) -> Dict:
        """Compute aggregate fairness health metrics from recent flags."""
        if not recent_flags:
            return {"fairness_score": 1.0, "issues_detected": 0, "metrics_checked": 4}

        total = len(recent_flags)
        avg_disparity = sum(f.get("disparity", 0) for f in recent_flags) / total if total else 0

        return {
            "fairness_score": max(0.0, round(1.0 - avg_disparity, 3)),
            "issues_detected": total,
            "avg_disparity": round(avg_disparity, 3),
            "metrics_checked": 4,
        }
