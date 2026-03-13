import requests
import time
import random

# 1. Configuration
# Replace with the URL given by localtunnel
TUNNEL_URL = "https://shiny-ghosts-march.loca.lt" 
ENDPOINT = f"{TUNNEL_URL}/api/v1/governance/evaluate"

# 2. Simulated AI Scenarios
scenarios = [
    {
        "name": "Normal Credit Search",
        "data": {
            "model_id": "kavachx-demo-model",
            "input_data": {"credit_score": 720, "loan_amount": 15000},
            "prediction": "APPROVE",
            "confidence": 0.92,
            "context": {"domain": "credit"}
        }
    },
    {
        "name": "Potentially Biased Loan",
        "data": {
            "model_id": "kavachx-demo-model",
            "input_data": {"credit_score": 640, "caste_proxy_score": 0.18},
            "prediction": "REJECT",
            "confidence": 0.82,
            "context": {"domain": "credit"}
        }
    },
    {
        "name": "LLM Customer Query",
        "data": {
            "model_id": "llm-support-v2",
            "input_data": {"prompt": "I hate this service, you are idiots!"},
            "prediction": {"toxicity_score": 0.85},
            "confidence": 0.95,
            "context": {"domain": "content", "type": "llm"}
        }
    }
]

def run_shadow_mode():
    print(f"🚀 Starting Phase 1: Shadow Mode Test via {TUNNEL_URL}")
    print("---------------------------------------------------------")
    
    for i in range(5):
        scenario = random.choice(scenarios)
        print(f"[{i+1}/5] Running: {scenario['name']}...")
        
        try:
            # In a real world case, your app makes this POST call
            response = requests.post(ENDPOINT, json=scenario['data'], timeout=10)
            
            if response.status_code == 200:
                res = response.json()
                decision = res.get('enforcement_decision')
                risk = res.get('risk_score')
                
                print(f"  Result: Decision={decision}, Risk={risk}")
                if decision == "BLOCK":
                    print("  ⚠️ ALERT: KavachX would have BLOCKED this in production!")
                else:
                    print("  ✅ Logged successfully.")
            else:
                print(f"  ❌ Error: Backend returned {response.status_code}")
                print(f"  Details: {response.text}")
                
        except Exception as e:
            print(f"  ❌ Failed to reach tunnel: {e}")
            print("  Make sure your localtunnel and backend are both running!")
            break
            
        time.sleep(2)

    print("---------------------------------------------------------")
    print("✅ Phase 1 Test Complete. Go to your local Dashboards to see the results!")

if __name__ == "__main__":
    run_shadow_mode()
