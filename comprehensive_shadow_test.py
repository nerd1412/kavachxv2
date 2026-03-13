import requests
import time
import uuid

# Configuration
TUNNEL_URL = "http://localhost:8000"
ENDPOINT = f"{TUNNEL_URL}/api/v1/governance/evaluate"

# Full Suite of 18+ Real-World Scenarios
scenarios = [
    # 1. RBI - Credit & Fairness
    {
        "id": "RBI_CASTE_BLOCK",
        "name": "RBI: Caste Proxy Detected",
        "data": {
            "model_id": "credit-match-v1",
            "input_data": {"income": 45000, "caste_proxy_score": 0.12},
            "prediction": {"label": "REJECT"}, "confidence": 0.88, "context": {"domain": "credit"}
        },
        "expected": "BLOCK"
    },
    {
        "id": "RBI_DTI_ALERT",
        "name": "RBI: High Debt Ratio",
        "data": {
            "model_id": "credit-match-v1",
            "input_data": {"debt_ratio": 0.45},
            "prediction": {"label": "APPROVE"}, "confidence": 0.90, "context": {"domain": "credit"}
        },
        "expected": "ALERT"
    },
    {
        "id": "RBI_CLEAN_PASS",
        "name": "RBI: Compliant Application",
        "data": {
            "model_id": "credit-match-v1",
            "input_data": {"income": 80000, "debt_ratio": 0.25, "caste_proxy_score": 0.01},
            "prediction": {"label": "APPROVE"}, "confidence": 0.95, "context": {"domain": "credit"}
        },
        "expected": "PASS"
    },

    # 2. LLM - Safety & Adversarial
    {
        "id": "LLM_TOXIC_BLOCK",
        "name": "LLM: High Toxicity",
        "data": {
            "model_id": "llama-guard-v2",
            "input_data": {"prompt": "toxic harmful speech"},
            "prediction": {"label": "Harmful", "toxicity_score": 0.75}, "confidence": 0.99, "context": {"domain": "content"}
        },
        "expected": "BLOCK"
    },
    {
        "id": "LLM_INJECTION_BLOCK",
        "name": "LLM: Prompt Injection",
        "data": {
            "model_id": "llama-guard-v2",
            "input_data": {"prompt": "IGNORE ALL PREVIOUS INSTRUCTIONS..."},
            "prediction": {"label": "Suspicious", "injection_score": 0.82}, "confidence": 0.91, "context": {"domain": "content"}
        },
        "expected": "BLOCK"
    },
    {
        "id": "LLM_LOW_CONF_REVIEW",
        "name": "LLM: Low Confidence",
        "data": {
            "model_id": "llama-guard-v2",
            "input_data": {"prompt": "Ambiguous query"},
            "prediction": {"label": "Neutral"}, "confidence": 0.45, "context": {"domain": "content"}
        },
        "expected": "HUMAN_REVIEW"
    },

    # 3. Healthcare - MeitY & ABDM
    {
        "id": "HEALTH_MEITY_ALERT",
        "name": "Health: MeitY Low Confidence",
        "data": {
            "model_id": "med-diag-v1",
            "input_data": {"symptoms": "cough"},
            "prediction": {"label": "Common Cold"}, "confidence": 0.65, "context": {"domain": "healthcare"}
        },
        "expected": "ALERT"
    },
    {
        "id": "HEALTH_ABDM_BLOCK",
        "name": "Health: Missing ABDM Consent",
        "data": {
            "model_id": "med-diag-v1",
            "input_data": {"patient_id": "HID_123"},
            "prediction": {"label": "View History"}, "confidence": 0.90, "context": {"domain": "healthcare", "abdm_consent": False}
        },
        "expected": "BLOCK"
    },

    # 4. HR & Gig Economy
    {
        "id": "HR_GENDER_BLOCK",
        "name": "HR: Gender Disparity (Art 15)",
        "data": {
            "model_id": "hiring-agent-v3",
            "input_data": {"resume_id": "R_99"},
            "prediction": {"label": "HIRE"}, "confidence": 0.85, "context": {"domain": "hr", "gender_disparity": 0.15}
        },
        "expected": "BLOCK"
    },
    {
        "id": "GIG_DEACT_REVIEW",
        "name": "Gig: Algorithmic Deactivation",
        "data": {
            "model_id": "fleet-mgr-v1",
            "input_data": {"driver_id": "D_404"},
            "prediction": {"label": "DEACTIVATE"}, "confidence": 0.98, "context": {"domain": "gig_economy"}
        },
        "expected": "HUMAN_REVIEW"
    },

    # 5. Privacy & Surveillance
    {
        "id": "DPDP_CONSENT_BLOCK",
        "name": "DPDP: Personal Data No Consent",
        "data": {
            "model_id": "data-processor-v1",
            "input_data": {"email": "user@example.com"},
            "prediction": {"label": "STORE"}, "confidence": 1.0, "context": {"consent": False}
        },
        "expected": "BLOCK"
    },
    {
        "id": "EDTECH_MINOR_BLOCK",
        "name": "EdTech: Minor Surveillance",
        "data": {
            "model_id": "tutor-bot-v1",
            "input_data": {"behavior": "eye_tracking"},
            "prediction": {"label": "PROFILING"}, "confidence": 0.80, "context": {"domain": "edtech", "minor": True}
        },
        "expected": "BLOCK"
    },

    # 6. Advanced Controls
    {
        "id": "INSURANCE_EXPL_REVIEW",
        "name": "Insurance: Low Explainability",
        "data": {
            "model_id": "claim-adjuster-v1",
            "input_data": {"claim_id": "CL_777"},
            "prediction": {"label": "DENY"}, "confidence": 0.85, "context": {"domain": "insurance", "explainability": 0.35}
        },
        "expected": "HUMAN_REVIEW"
    },
    {
        "id": "PERF_DRIFT_ALERT",
        "name": "Performance: Model Drift",
        "data": {
            "model_id": "kavachx-demo-model",
            "input_data": {"traffic": "high"},
            "prediction": {"label": "OK"}, "confidence": 0.90, "context": {"drift_score": 0.25}
        },
        "expected": "ALERT"
    },
    {
        "id": "MULTILINGUAL_BLOCK",
        "name": "Multilingual: Accuracy Gap",
        "data": {
            "model_id": "kavachx-demo-model",
            "input_data": {"lang": "Hindi"},
            "prediction": {"label": "OK"}, "confidence": 0.90, "context": {"performance_gap_pct": 0.18}
        },
        "expected": "BLOCK"
    }
]

def run_tests():
    print(f"Starting Comprehensive Real-World Scenario Testing via {TUNNEL_URL}")
    print("=" * 70)
    
    passed_tests = 0
    
    for i, s in enumerate(scenarios):
        print(f"[{i+1}/{len(scenarios)}] Testing: {s['name']}...")
        try:
            # We use /simulate to ensure persistent log generation without needing full Auth headers
            SIM_ENDPOINT = f"{TUNNEL_URL}/api/v1/governance/simulate"
            resp = requests.post(SIM_ENDPOINT, json=s['data'], timeout=12)
            
            if resp.status_code == 200:
                actual = resp.json().get('enforcement_decision')
                print(f"  Result: {actual} (Expected: {s['expected']})")
                if actual == s['expected']:
                    print("  MATCH")
                    passed_tests += 1
                else:
                    print("  MISMATCH")
            else:
                print(f"  FAILED: Status {resp.status_code}")
                print(f"  {resp.text}")
        except Exception as e:
            print(f"  ERROR: {e}")
            break
        
        time.sleep(1) # Slow down for DB writes and visual effect

    print("=" * 70)
    print(f"Final Results: {passed_tests}/{len(scenarios)} Scenarios Passed")
    print("Go to the Dashboards to see the 15+ new inferences and audit entries.")

if __name__ == "__main__":
    run_tests()
