/**
 * KavachX Browser Extension — Background Worker (Final v3.9)
 * Receives intercepted prompts and evaluates them against the Governance Engine.
 */

// Production API Endpoint (Using Port 8002 to match the new isolated backend)
const KAVACHX_API_URL = 'http://127.0.0.1:8002/api/v1/governance/simulate';

function normalizePlatform(hostname) {
  const host = (hostname || '').toLowerCase();
  if (host.includes('chatgpt.com') || host.includes('chat.openai.com')) return 'chatgpt';
  if (host.includes('claude.ai')) return 'claude';
  if (host.includes('gemini.google.com') || host.includes('bard.google.com')) return 'gemini';
  if (host.includes('copilot.microsoft.com')) return 'copilot';
  return 'universal-ai';
}

async function getSessionId() {
  const res = await chrome.storage.local.get(['kavach_session_id']);
  if (res.kavach_session_id) return res.kavach_session_id;
  const id = self.crypto.randomUUID();
  await chrome.storage.local.set({ kavach_session_id: id });
  return id;
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action !== 'evaluate_prompt') return false;

  const url = new URL(sender.tab?.url || 'https://universal-ai.com');
  const platform = normalizePlatform(url.hostname);
  const prompt = request.prompt || '';

  console.log(`🛡️ Kavach Interceptor: Evaluating on ${platform}`);

  (async () => {
    try {
      const sessionId = await getSessionId();
      const response = await fetch(KAVACHX_API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model_id: 'kavach-sentinel-v1',
          session_id: sessionId,
          input_data: { 
            prompt, 
            source: 'extension', 
            platform 
          },
          // Hardened Simulation Payload (Satisfies Backend Pydantic)
          prediction: { text: "Simulated Prediction" },
          confidence: 0.95,
          context: { 
            domain: 'external_governance', 
            platform, 
            jurisdiction: 'IN',
            shadow_ai_detected: true
          }
        }),
      });

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      
      const decision = result.enforcement_decision || 'PASS';
      const reason = result.policy_violations?.[0]?.message || 'Policy violation detected.';

      if (decision === 'BLOCK') {
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon128.png',
          title: '🚨 Kavach — BLOCKED',
          message: `${platform.toUpperCase()}: ${reason}`,
          priority: 2
        });
      }

      sendResponse({ decision, reason });
    } catch (err) {
      console.error('❌ Kavach Connectivity Error:', err.message);
      // Hard fail-closed for security: block if engine is offline
      sendResponse({ decision: 'BLOCK', reason: 'KavachX Engine Offline — Access Denied for Safety.' });
    }
  })();

  return true; // Keep async channel open
});
