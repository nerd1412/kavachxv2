"""
KavachX Demo Data Seeder v2.0
Seeds models, policies, and inference events for all role testing.
"""
import asyncio
import httpx
import random

BASE_URL = "http://localhost:8000"

DEMO_MODELS = [
    {"name": "credit-scoring-v3", "version": "v3.1.0", "model_type": "classification", "owner": "ml-team@kavachx.ai", "description": "Credit risk scoring for loan applications"},
    {"name": "hiring-screener-v2", "version": "v2.0.1", "model_type": "classification", "owner": "hr-ml@kavachx.ai", "description": "Resume screening and candidate ranking"},
    {"name": "medical-diagnosis-ai", "version": "v1.2.0", "model_type": "classification", "owner": "health-ml@kavachx.ai", "description": "Medical symptom risk assessment"},
    {"name": "content-moderation-llm", "version": "v4.0.0", "model_type": "llm", "owner": "trust-safety@kavachx.ai", "description": "LLM-based content safety classifier"},
    {"name": "loan-approval-ml", "version": "v2.3.0", "model_type": "classification", "owner": "credit-ml@kavachx.ai", "description": "End-to-end loan approval model"},
]

SCENARIOS = [
    {"confidence": 0.91, "prediction": {"label": "APPROVE"}, "context": {"domain": "credit"}, "features": {"credit_score": 750, "income": 85000}},
    {"confidence": 0.55, "prediction": {"label": "REJECT"}, "context": {"domain": "credit"}, "features": {"credit_score": 580, "income": 22000}},
    {"confidence": 0.68, "prediction": {"label": "APPROVE"}, "context": {"domain": "credit"}, "features": {"credit_score": 640, "income": 48000}},
    {"confidence": 0.42, "prediction": {"label": "UNCERTAIN"}, "context": {}, "features": {"feature_a": 0.4}},
    {"confidence": 0.85, "prediction": {"label": "ADVANCE"}, "context": {"domain": "hiring"}, "features": {"years_experience": 7, "skills_match": 0.9}},
    {"confidence": 0.73, "prediction": {"label": "REJECT"}, "context": {"domain": "hiring"}, "features": {"years_experience": 2}},
    {"confidence": 0.97, "prediction": {"label": "SAFE", "toxicity_score": 0.02}, "context": {"domain": "content"}, "features": {"prompt": "Hello"}},
    {"confidence": 0.54, "prediction": {"label": "FLAGGED", "toxicity_score": 0.78}, "context": {"domain": "content"}, "features": {"prompt": "Risky content"}},
]


async def main():
    print("🌱 Seeding KavachX demo data...")
    async with httpx.AsyncClient(timeout=30) as client:
        # Register models
        model_ids = []
        for m in DEMO_MODELS:
            try:
                r = await client.post(f"{BASE_URL}/api/v1/models/", json=m)
                if r.status_code in (200, 201):
                    model_ids.append(r.json()["id"])
                    print(f"  ✅ Model: {m['name']}")
            except Exception as e:
                print(f"  ⚠️  {m['name']}: {e}")

        if not model_ids:
            print("❌ No models registered. Is the backend running?")
            return

        # Run inferences
        print(f"\n🔄 Running {len(SCENARIOS) * 3} inference events...")
        count = 0
        for model_id in model_ids[:3]:
            for sc in SCENARIOS[:6]:
                try:
                    payload = {
                        "model_id": model_id,
                        "input_data": sc["features"],
                        "prediction": sc["prediction"],
                        "confidence": sc["confidence"] + random.uniform(-0.05, 0.05),
                        "context": sc["context"],
                    }
                    r = await client.post(f"{BASE_URL}/api/v1/governance/evaluate", json=payload)
                    if r.status_code == 200:
                        d = r.json()
                        print(f"  [{d.get('enforcement_decision','?'):12}] conf={payload['confidence']:.2f} risk={d.get('risk_score',0):.2f}")
                        count += 1
                except Exception as e:
                    print(f"  ⚠️  Inference failed: {e}")

        print(f"\n✨ Done! Seeded {len(model_ids)} models and {count} inferences.")
        print("   Login at http://localhost:5173")
        print("   API docs at http://localhost:8000/docs")


if __name__ == "__main__":
    asyncio.run(main())
