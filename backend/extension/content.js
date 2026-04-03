/**
 * KavachX Browser Extension — Precision Interceptor (v7)
 *
 * Fix v6 → v7: Re-dispatch loop resolved.
 * - After PASS/ALERT, we find and CLICK the real Send button instead of
 *   simulating a keyboard event (which gets caught by the interceptor again).
 * - A `bypassing` flag at the very top of the handler prevents any
 *   re-entry during the release window.
 * - Only `enforcement_decision === "BLOCK"` stops the prompt.
 */

(function () {
  'use strict';

  if (window.__kavachxInjectedV7) return;
  window.__kavachxInjectedV7 = true;

  console.log('🛡️ Kavach AI Shield v7: Precision Interceptor Active');

  let evaluating = false; // True while waiting for backend response
  let bypassing  = false; // True during the release window (prevents re-interception)

  // ─── Shadow-DOM Aware Prompt Scraper ──────────────────────────────────────
  function findPrompt() {
    const SELECTORS = [
      '#prompt-textarea',
      'div[contenteditable="true"]',
      '.ProseMirror',
      '[role="textbox"]',
      'textarea'
    ];
    const findInRoot = (root) => {
      for (const s of SELECTORS) {
        const el = root.querySelector(s);
        if (el && el.offsetParent !== null) {
          const val = (el.value || el.innerText || el.textContent || '').trim();
          if (val.length > 2) return { el, text: val };
        }
      }
      for (const child of root.querySelectorAll('*')) {
        if (child.shadowRoot) {
          const found = findInRoot(child.shadowRoot);
          if (found) return found;
        }
      }
      return null;
    };
    return findInRoot(document);
  }

  // ─── Find the real Send button ────────────────────────────────────────────
  function findSendButton() {
    // ChatGPT, Claude, Gemini, Copilot — ordered by specificity
    const SEND_SELECTORS = [
      '[data-testid="send-button"]',
      'button[aria-label="Send prompt"]',
      'button[aria-label="Send message"]',
      'button[aria-label="Send"]',
      'button[type="submit"]',
      'button.send-button',
      'form button:last-of-type',
    ];
    for (const s of SEND_SELECTORS) {
      const btn = document.querySelector(s);
      if (btn && !btn.disabled) return btn;
    }
    return null;
  }

  // ─── Release (PASS / ALERT) ───────────────────────────────────────────────
  function releasePrompt() {
    bypassing = true;

    // Strategy 1: click the real send button
    const sendBtn = findSendButton();
    if (sendBtn) {
      console.log('🛡️ [Kavach] Releasing via Send button click');
      sendBtn.click();
      setTimeout(() => { bypassing = false; }, 800);
      return;
    }

    // Strategy 2: requestSubmit() on the form
    const form = document.querySelector('form');
    if (form) {
      console.log('🛡️ [Kavach] Releasing via form.requestSubmit()');
      try { form.requestSubmit(); } catch (_) { form.submit(); }
      setTimeout(() => { bypassing = false; }, 800);
      return;
    }

    // Strategy 3: dispatch Enter on document.activeElement
    console.log('🛡️ [Kavach] Releasing via Enter on active element');
    const target = document.activeElement || document.body;
    target.dispatchEvent(new KeyboardEvent('keydown', {
      key: 'Enter', code: 'Enter', keyCode: 13,
      which: 13, bubbles: true, cancelable: false
    }));
    setTimeout(() => { bypassing = false; }, 800);
  }

  // ─── Security Banner ──────────────────────────────────────────────────────
  function showBanner(msg) {
    document.getElementById('kavachx-block-alert')?.remove();
    const b = document.createElement('div');
    b.id = 'kavachx-block-alert';
    b.style.cssText = [
      'position:fixed', 'top:30px', 'left:50%', 'transform:translateX(-50%)',
      'background:#0f0f0f', 'color:#f87171', 'padding:18px 28px',
      'border-radius:12px', 'z-index:2147483647', 'font-family:system-ui,sans-serif',
      'box-shadow:0 12px 40px rgba(0,0,0,0.8)', 'border:2px solid #ef4444',
      'text-align:center', 'max-width:440px', 'line-height:1.5'
    ].join(';');
    b.innerHTML = `
      <strong>🚨 KAVACH SECURITY BLOCK</strong>
      <div style="margin-top:8px;font-size:14px;opacity:0.92;">${msg}</div>
    `;
    document.body.appendChild(b);
    setTimeout(() => {
      b.style.transition = 'opacity 0.5s';
      b.style.opacity = '0';
      setTimeout(() => b.remove(), 500);
    }, 7000);
  }

  // ─── Main Interceptor ─────────────────────────────────────────────────────
  function handler(e) {
    // GUARD 1: We are in the release window — let the event through untouched
    if (bypassing) return;

    // GUARD 2: Debounce — we are already waiting for a backend response
    if (evaluating) {
      e.preventDefault();
      e.stopImmediatePropagation();
      return;
    }

    // Key filter: only Enter without Shift
    if (e.type === 'keydown' && (e.key !== 'Enter' || e.shiftKey)) return;

    // Click filter: only the Send button area
    if (['click', 'mousedown', 'pointerdown'].includes(e.type)) {
      const btn = e.target.closest('button, [role="button"], [data-testid*="send"], svg');
      if (!btn) return;
    }

    const result = findPrompt();
    if (!result || result.text.length < 3) return;

    // INTERCEPT
    e.preventDefault();
    e.stopImmediatePropagation();
    evaluating = true;

    console.log(`🛡️ [Kavach] Intercepted: "${result.text.substring(0, 45)}..."`);

    chrome.runtime.sendMessage(
      { action: 'evaluate_prompt', prompt: result.text, domain: window.location.hostname },
      (response) => {
        evaluating = false;

        if (chrome.runtime.lastError || !response) {
          console.warn('🛡️ [Kavach] Engine unreachable — blocking for safety');
          showBanner('Governance Engine Offline — Prompt Blocked for Safety');
          return;
        }

        const decision = (response.decision || 'PASS').toUpperCase();
        console.log(`🛡️ [Kavach] Decision: ${decision}`);

        if (decision === 'BLOCK') {
          showBanner(response.reason || 'Blocked by KavachX Governance Policy');
        } else {
          // PASS or ALERT → release silently, audit log written to dashboard
          releasePrompt();
        }
      }
    );
  }

  // Capture phase on all relevant events
  ['keydown', 'click', 'mousedown'].forEach(type => {
    document.addEventListener(type, handler, true);
  });

})();
