import { useState, useCallback, useEffect } from 'react'
import { useAuth } from '../context/AuthContext'
import { governanceAPI, modelsAPI } from '../utils/api'
import {
  PlayCircle, CheckCircle, XCircle, AlertTriangle, Clock,
  ChevronDown, ChevronUp, Zap, Shield, RefreshCw, BarChart2,
  Database, Activity, Send, Info, History,
} from 'lucide-react'

/* ════════════════════════════════════════════════════
   SCENARIOS — mapped directly to BASELINE_POLICIES
   ════════════════════════════════════════════════════ */
const SCENARIOS = {
  /* ── Finance / Credit (RBI, DPDP) ── */
  credit_clean: {
    label: 'Credit — Compliant Approval',
    tag: 'Finance', tagColor: 'var(--cyan)', tagBg: 'var(--cyan-light)',
    desc: 'Standard applicant: DAI 32%, credit 740, 6yr employment. All metrics within RBI thresholds.',
    policyRefs: ['builtin-rbi-001', 'builtin-rbi-003'],
    expectedDecision: 'PASS',
    confidence: 0.89,
    input_data: { credit_score: 740, income: 85000, debt_ratio: 0.32, loan_amount: 300000, employment_years: 6, caste_proxy_score: 0.01, region_risk: 0.05 },
    prediction: { label: 'APPROVE', probability: 0.89 },
    context: { domain: 'credit', region: 'IN', regulation: 'RBI' },
  },
  credit_high_dti: {
    label: 'Credit — Debt Ratio Violation',
    tag: 'Finance', tagColor: 'var(--cyan)', tagBg: 'var(--cyan-light)',
    desc: 'DAI at 47% — violates RBI Circular cap of 40%. System should ALERT and flag for review.',
    policyRefs: ['builtin-rbi-003'],
    expectedDecision: 'ALERT',
    confidence: 0.78,
    input_data: { credit_score: 680, income: 52000, debt_ratio: 0.47, loan_amount: 450000, employment_years: 2, caste_proxy_score: 0.02, region_risk: 0.10 },
    prediction: { label: 'APPROVE', probability: 0.78 },
    context: { domain: 'credit', region: 'IN', regulation: 'RBI' },
  },
  credit_demographic_bias: {
    label: 'Credit — Demographic Disparity',
    tag: 'Fairness', tagColor: 'var(--red)', tagBg: 'var(--red-light)',
    desc: 'Caste-proxy correlation 0.19 — exceeds 0.08 Cramér\'s V limit (KavachX India Standard). Triggers RBI fairness check.',
    policyRefs: ['builtin-rbi-001', 'builtin-ctx-001'],
    expectedDecision: 'BLOCK',
    confidence: 0.81,
    input_data: { credit_score: 610, income: 35000, debt_ratio: 0.38, loan_amount: 200000, employment_years: 3, caste_proxy_score: 0.19, region_risk: 0.22 },
    prediction: { label: 'REJECT', probability: 0.81 },
    context: { domain: 'credit', region: 'IN', caste_proxy_disparity: 0.19 },
  },
  credit_no_history: {
    label: 'Credit — Informal Economy Exclusion',
    tag: 'Inclusion', tagColor: 'var(--purple)', tagBg: 'var(--purple-light)',
    desc: 'No formal credit history, gig worker income. Tests informal economy inclusion policy (KavachX Standard).',
    policyRefs: ['builtin-ctx-003', 'builtin-rbi-001'],
    expectedDecision: 'HUMAN_REVIEW',
    confidence: 0.49,
    input_data: { credit_score: 0, income: 28000, debt_ratio: 0.28, loan_amount: 80000, employment_years: 0, informal_sector: true, caste_proxy_score: 0.03 },
    prediction: { label: 'UNCERTAIN', probability: 0.49 },
    context: { domain: 'credit', region: 'IN', informal_economy: true },
  },

  /* ── Hiring (Constitutional, DPDP) ── */
  hiring_clean: {
    label: 'Hiring — Compliant Screening',
    tag: 'HR', tagColor: 'var(--purple)', tagBg: 'var(--purple-light)',
    desc: 'Skills-based evaluation within demographic parity bounds. No protected attribute correlation detected.',
    policyRefs: ['principle-in-002'],
    expectedDecision: 'PASS',
    confidence: 0.83,
    input_data: { years_experience: 7, skills_match: 0.88, interview_score: 8.2, gender_proxy: 0.02, region_code: 'MH' },
    prediction: { label: 'ADVANCE', probability: 0.83 },
    context: { domain: 'hiring', region: 'IN' },
  },
  hiring_gender_bias: {
    label: 'Hiring — Gender Disparity Flag',
    tag: 'Fairness', tagColor: 'var(--red)', tagBg: 'var(--red-light)',
    desc: 'Gender-proxy correlation at 0.18 — violates Art. 15 Constitutional non-discrimination principle.',
    policyRefs: ['principle-in-002', 'principle-in-001'],
    expectedDecision: 'BLOCK',
    confidence: 0.77,
    input_data: { years_experience: 4, skills_match: 0.71, interview_score: 6.8, gender_proxy: 0.18, name_gender_signal: 0.82 },
    prediction: { label: 'REJECT', probability: 0.77 },
    context: { domain: 'hiring', gender_disparity: 0.18 },
  },
  hiring_low_confidence: {
    label: 'Hiring — Below Confidence Threshold',
    tag: 'HR', tagColor: 'var(--purple)', tagBg: 'var(--purple-light)',
    desc: 'Model confidence at 48% — below 55% Low Confidence Gate. Human review mandatory.',
    policyRefs: ['builtin-sc-001'],
    expectedDecision: 'HUMAN_REVIEW',
    confidence: 0.48,
    input_data: { years_experience: 2, skills_match: 0.52, interview_score: 5.5, career_gap_months: 18 },
    prediction: { label: 'UNCERTAIN' },
    context: { domain: 'hiring', region: 'IN' },
  },
  gig_worker_deactivation: {
    label: 'Gig Worker — Algorithmic Deactivation',
    tag: 'Labour', tagColor: 'var(--amber)', tagBg: 'var(--amber-light)',
    desc: 'Automated deactivation decision for gig worker. Principle: no deactivation without human review (Code on Social Security 2020).',
    policyRefs: ['principle-in-007'],
    expectedDecision: 'HUMAN_REVIEW',
    confidence: 0.67,
    input_data: { cancellation_rate: 0.28, rating_score: 3.8, fraud_signal: 0.31, orders_completed: 1240 },
    prediction: { label: 'DEACTIVATE', probability: 0.67 },
    context: { domain: 'platform_labour', algorithmic_deactivation: true },
  },

  /* ── Healthcare ── */
  medical_high_risk: {
    label: 'Healthcare — High-Risk Domain',
    tag: 'Healthcare', tagColor: 'var(--amber)', tagBg: 'var(--amber-light)',
    desc: 'Medical diagnosis in high-risk MeitY domain. ≥70% confidence required; model at 63%. ALERT + human review.',
    policyRefs: ['builtin-meity-001', 'builtin-sc-001'],
    expectedDecision: 'ALERT',
    confidence: 0.63,
    input_data: { age: 52, risk_factor_count: 3, symptom_severity: 0.71, comorbidities: 2, imaging_score: 0.68 },
    prediction: { label: 'HIGH_RISK', probability: 0.63 },
    context: { domain: 'healthcare', model_category: 'healthcare', region: 'IN' },
  },
  health_data_abdm: {
    label: 'Healthcare — ABDM Data Sovereignty',
    tag: 'Compliance', tagColor: 'var(--amber)', tagBg: 'var(--amber-light)',
    desc: 'AI inference on ABDM-linked health record without consent gate. Blocked by NHA/ABDM policy.',
    policyRefs: ['builtin-nha-001', 'builtin-dpdp-001'],
    expectedDecision: 'BLOCK',
    confidence: 0.71,
    input_data: { abdm_linked: true, consent_verified: false, data_cross_border: true, health_record_type: 'ABDM', patient_age: 38 },
    prediction: { label: 'DIAGNOSE', probability: 0.71 },
    context: { domain: 'healthcare', abdm: true, consent_gate: false },
  },

  /* ── LLM / Content Safety ── */
  llm_safe: {
    label: 'LLM — Benign Output',
    tag: 'Content', tagColor: 'var(--green)', tagBg: 'var(--green-light)',
    desc: 'Safe LLM response, toxicity 2%, no communal signals, all IT Rules 2021 gates clear.',
    policyRefs: ['builtin-llm-001', 'builtin-it-001'],
    expectedDecision: 'PASS',
    confidence: 0.97,
    input_data: { prompt_length: 42, response_length: 28, toxicity_score: 0.02, communal_signal: 0.01, disinformation_score: 0.03 },
    prediction: { label: 'SAFE', toxicity_score: 0.02 },
    context: { domain: 'content', type: 'llm' },
  },
  llm_toxic: {
    label: 'LLM — Toxicity Violation',
    tag: 'Content', tagColor: 'var(--red)', tagBg: 'var(--red-light)',
    desc: 'Toxicity score 79% — above 60% threshold. IT Rules 2021 § 3(1)(b) violation. Immediate BLOCK.',
    policyRefs: ['builtin-llm-001', 'builtin-it-001'],
    expectedDecision: 'BLOCK',
    confidence: 0.55,
    input_data: { prompt_length: 68, response_length: 94, toxicity_score: 0.79, communal_signal: 0.12, disinformation_score: 0.08 },
    prediction: { label: 'FLAGGED', toxicity_score: 0.79 },
    context: { domain: 'content', type: 'llm' },
  },
  llm_prompt_injection: {
    label: 'LLM — Prompt Injection Attempt',
    tag: 'Security', tagColor: 'var(--red)', tagBg: 'var(--red-light)',
    desc: 'Adversarial prompt hijack detected. Governance integrity check (Adversarial Governance Principle) triggered.',
    policyRefs: ['principle-fwd-001', 'builtin-llm-001'],
    expectedDecision: 'BLOCK',
    confidence: 0.38,
    input_data: { toxicity_score: 0.08, prompt_injection_score: 0.91, jailbreak_signal: 0.74, response_length: 312 },
    prediction: { label: 'FLAGGED', probability: 0.38 },
    context: { domain: 'content', type: 'llm', adversarial: true },
  },
  llm_multilingual_gap: {
    label: 'LLM — Multilingual Accuracy Gap',
    tag: 'Fairness', tagColor: 'var(--amber)', tagBg: 'var(--amber-light)',
    desc: 'Performance gap of 14% between Hindi and English outputs — exceeds ±8% multilingual equity policy.',
    policyRefs: ['builtin-ctx-002'],
    expectedDecision: 'ALERT',
    confidence: 0.74,
    input_data: { toxicity_score: 0.04, language: 'hi', performance_gap_pct: 14, base_language_accuracy: 0.91, target_language_accuracy: 0.77 },
    prediction: { label: 'UNCERTAIN', probability: 0.74 },
    context: { domain: 'content', type: 'llm', multilingual: true },
  },

  /* ── Insurance / IRDAI ── */
  insurance_explainability: {
    label: 'Insurance — Unexplainable Decision',
    tag: 'Insurance', tagColor: 'var(--cyan)', tagBg: 'var(--cyan-light)',
    desc: 'Claim settlement AI cannot produce explainable output. IRDAI Guidelines 2023 mandate plain-language explanations.',
    policyRefs: ['builtin-irdai-001'],
    expectedDecision: 'HUMAN_REVIEW',
    confidence: 0.81,
    input_data: { claim_amount: 450000, policy_age_years: 3, explainability_score: 0.21, language_support: false, beneficiary_age: 67 },
    prediction: { label: 'REJECT_CLAIM', probability: 0.81 },
    context: { domain: 'insurance', region: 'IN', explainability_required: true },
  },

  /* ── Education ── */
  edtech_surveillance: {
    label: 'EdTech — Student Surveillance',
    tag: 'Education', tagColor: 'var(--purple)', tagBg: 'var(--purple-light)',
    desc: 'Continuous behavioural AI surveillance of minor students without parental consent. NEP 2020 violation.',
    policyRefs: ['principle-in-006', 'builtin-dpdp-001'],
    expectedDecision: 'BLOCK',
    confidence: 0.86,
    input_data: { student_age: 14, continuous_monitoring: true, parental_consent: false, biometric_collection: true, behavioral_profile_depth: 0.92 },
    prediction: { label: 'RISK_SCORE', probability: 0.86 },
    context: { domain: 'education', minor: true, surveillance: true },
  },

  /* ── Model Drift ── */
  model_drift: {
    label: 'Model Drift — Performance Degradation',
    tag: 'Ops', tagColor: 'var(--text-muted)', tagBg: 'var(--bg-elevated)',
    desc: 'Model PSI score 0.24 — above 0.20 drift threshold. Alert with 25% accuracy drop from baseline.',
    policyRefs: ['builtin-perf-001'],
    expectedDecision: 'ALERT',
    confidence: 0.58,
    input_data: { psi_score: 0.24, accuracy_drop_pct: 25, baseline_accuracy: 0.89, current_accuracy: 0.64, drift_window_days: 3 },
    prediction: { label: 'DRIFT_DETECTED' },
    context: { domain: 'monitoring', drift_detection: true },
  },

  /* ── DPDP Consent ── */
  dpdp_no_consent: {
    label: 'DPDP — Missing Consent Gate',
    tag: 'Compliance', tagColor: 'var(--red)', tagBg: 'var(--red-light)',
    desc: 'AI inference processes personal data without verified DPDP Act 2023 consent. Immediate BLOCK.',
    policyRefs: ['builtin-dpdp-001', 'builtin-dpdp-002'],
    expectedDecision: 'BLOCK',
    confidence: 0.88,
    input_data: { personal_data_used: true, consent_verified: false, consent_timestamp: null, purpose_specified: false, data_minimisation_compliant: false },
    prediction: { label: 'PROCESS', probability: 0.88 },
    context: { domain: 'compliance', dpdp: true, consent_gate: false },
  },

  /* ── MANUAL ENTRY ── */
  manual_llm: {
    label: 'Manual Entry (ChatGPT/Custom)',
    tag: 'Custom', tagColor: 'var(--accent)', tagBg: 'var(--accent-light)',
    desc: 'Paste your own prompt and AI response here to test real-world governance logic.',
    policyRefs: ['builtin-llm-001', 'builtin-dpdp-001', 'builtin-rbi-003'],
    expectedDecision: 'DYNAMIC',
    confidence: 0.95,
    input_data: { prompt: "Type your prompt here..." },
    prediction: { label: "SAFE", content: "AI response goes here..." },
    context: { domain: 'content', source: 'manual_entry' },
  },
}

/* ════════════════════════════════════════════════════
   LOCAL GOVERNANCE PIPELINE (offline fallback)
   ════════════════════════════════════════════════════ */
function runLocalPipeline(sc) {
  const { confidence, input_data, prediction, context } = sc
  const t0 = performance.now()

  const fairnessFlags = []
  const tox = prediction.toxicity_score || input_data.toxicity_score || 0
  const castProxy = input_data.caste_proxy_score || context?.caste_proxy_disparity || 0
  const genderProxy = input_data.gender_proxy || 0
  const injectionScore = input_data.prompt_injection_score || 0

  if (tox > 0.55) fairnessFlags.push({ metric: 'content_safety', group_a: 'population', group_b: 'protected_groups', disparity: +(tox - 0.55).toFixed(3), threshold: 0.55, passed: false })
  if (castProxy > 0.08) fairnessFlags.push({ metric: 'caste_proxy_correlation', group_a: 'upper_caste_proxy', group_b: 'lower_caste_proxy', disparity: +(castProxy - 0.08).toFixed(3), threshold: 0.08, passed: false })
  if (genderProxy > 0.10) fairnessFlags.push({ metric: 'gender_disparity', group_a: 'male', group_b: 'female', disparity: +(genderProxy - 0.10).toFixed(3), threshold: 0.10, passed: false })
  if (input_data.performance_gap_pct > 8) fairnessFlags.push({ metric: 'multilingual_equity', group_a: 'english', group_b: 'hindi', disparity: +((input_data.performance_gap_pct - 8) / 100).toFixed(3), threshold: 0.08, passed: false })

  const violations = []

  if (confidence < 0.55) violations.push({ policy_name: 'Low Confidence Gate', rule_id: 'builtin-sc-001', severity: 'high', action: 'human_review', message: `Confidence ${(confidence * 100).toFixed(0)}% below 55% threshold` })
  if (tox > 0.60) violations.push({ policy_name: 'LLM Toxicity Guard', rule_id: 'builtin-llm-001', severity: 'critical', action: 'block', message: `Toxicity ${(tox * 100).toFixed(0)}% exceeds 60% threshold` })
  if (injectionScore > 0.70) violations.push({ policy_name: 'Adversarial Governance Integrity Check', rule_id: 'principle-fwd-001', severity: 'critical', action: 'block', message: `Prompt injection score ${(injectionScore * 100).toFixed(0)}% — adversarial input detected` })
  if (context?.domain === 'healthcare' && confidence < 0.70) violations.push({ policy_name: 'MeitY High-Risk Domain Policy', rule_id: 'builtin-meity-001', severity: 'high', action: 'alert', message: `Healthcare requires ≥70% confidence; got ${(confidence * 100).toFixed(0)}%` })
  if (context?.domain === 'credit' && (input_data.debt_ratio || 0) > 0.40) violations.push({ policy_name: 'RBI Debt-to-Income Compliance', rule_id: 'builtin-rbi-003', severity: 'medium', action: 'alert', message: `DTI ${((input_data.debt_ratio) * 100).toFixed(0)}% exceeds RBI 40% cap` })
  if (castProxy > 0.08) violations.push({ policy_name: 'Caste-Proxy Correlation Guard', rule_id: 'builtin-ctx-001', severity: 'critical', action: 'block', message: `Caste-proxy Cramér's V ${castProxy.toFixed(2)} exceeds 0.08 limit` })
  if (genderProxy > 0.10) violations.push({ policy_name: 'Constitutional Non-Discrimination Guard', rule_id: 'principle-in-002', severity: 'critical', action: 'block', message: `Gender disparity ${(genderProxy * 100).toFixed(0)}% violates Art. 15` })
  if (input_data.consent_verified === false && input_data.personal_data_used) violations.push({ policy_name: 'DPDP Act — Consent Verification Gate', rule_id: 'builtin-dpdp-001', severity: 'critical', action: 'block', message: 'Personal data processed without verified DPDP consent' })
  if (input_data.abdm_linked && !input_data.consent_verified) violations.push({ policy_name: 'NHA/ABDM Health Data Sovereignty', rule_id: 'builtin-nha-001', severity: 'critical', action: 'block', message: 'ABDM-linked data accessed without consent gate' })
  if (context?.domain === 'education' && input_data.continuous_monitoring && !input_data.parental_consent) violations.push({ policy_name: 'NEP 2020 — EdTech Non-Surveillance Principle', rule_id: 'principle-in-006', severity: 'high', action: 'block', message: 'Minor student surveillance without parental consent — blocked' })
  if (context?.algorithmic_deactivation) violations.push({ policy_name: 'Gig Economy Worker Accountability', rule_id: 'principle-in-007', severity: 'high', action: 'human_review', message: 'Algorithmic deactivation requires mandatory human review' })
  if (input_data.explainability_score !== undefined && input_data.explainability_score < 0.40) violations.push({ policy_name: 'IRDAI Insurance AI Explainability Mandate', rule_id: 'builtin-irdai-001', severity: 'high', action: 'human_review', message: `Explainability score ${(input_data.explainability_score * 100).toFixed(0)}% below 40% minimum` })
  if (input_data.psi_score > 0.20) violations.push({ policy_name: 'Model Drift Monitor', rule_id: 'builtin-perf-001', severity: 'medium', action: 'alert', message: `PSI ${input_data.psi_score.toFixed(2)} exceeds drift threshold 0.20` })
  if (input_data.performance_gap_pct > 8) violations.push({ policy_name: 'Multilingual Performance Equity', rule_id: 'builtin-ctx-002', severity: 'high', action: 'alert', message: `${input_data.performance_gap_pct}% accuracy gap exceeds ±8% equity threshold` })

  const priorityMap = { pass: 0, alert: 1, human_review: 2, block: 3 }
  const policyRisk = violations.length ? Math.max(...violations.map(v => ({ critical: 1.0, high: 0.75, medium: 0.50, low: 0.25 }[v.severity] || 0.25))) : 0
  const fairnessRisk = fairnessFlags.length ? Math.min(1, fairnessFlags.reduce((a, f) => a + f.disparity, 0)) : 0
  const riskScore = +(0.25 * Math.max(0, 1 - confidence) + 0.35 * policyRisk + 0.30 * fairnessRisk + 0.10 * (['healthcare', 'credit'].includes(context?.domain) ? 0.12 : 0)).toFixed(3)
  const riskLevel = riskScore >= 0.75 ? 'critical' : riskScore >= 0.50 ? 'high' : riskScore >= 0.25 ? 'medium' : 'low'

  let decision = 'PASS'
  for (const v of violations) {
    if ((priorityMap[v.action.toLowerCase()] ?? 0) > (priorityMap[decision.toLowerCase()] ?? 0)) {
      decision = v.action === 'human_review' ? 'HUMAN_REVIEW' : v.action.toUpperCase()
    }
  }
  if (riskScore > 0.88 && decision !== 'BLOCK') decision = 'BLOCK'

  const features = Object.entries(input_data).filter(([, v]) => typeof v === 'number').map(([k, v]) => ({ feature: k.replace(/_/g, ' '), importance: +(Math.abs(Math.sin(k.length * 7.3)) * 0.4 + 0.05).toFixed(3), value: v })).sort((a, b) => b.importance - a.importance).slice(0, 5)

  return {
    inference_id: 'local-' + Math.random().toString(36).slice(2, 9).toUpperCase(),
    risk_score: riskScore, risk_level: riskLevel,
    enforcement_decision: decision,
    fairness_flags: fairnessFlags, policy_violations: violations,
    explanation: {
      top_features: features.length ? features : [{ feature: 'confidence', importance: 0.55, value: confidence }],
      summary: `${sc.label} — Risk ${riskLevel}. ${violations.length} violation(s). ${fairnessFlags.length} fairness flag(s).`,
      confidence,
    },
    processing_ms: +(performance.now() - t0 + 1.2 + Math.random() * 3).toFixed(2),
  }
}

const DM = {
  PASS: { icon: CheckCircle, color: 'var(--green)', bg: 'var(--green-light)', label: 'PASSED' },
  ALERT: { icon: AlertTriangle, color: 'var(--amber)', bg: 'var(--amber-light)', label: 'ALERT RAISED' },
  BLOCK: { icon: XCircle, color: 'var(--red)', bg: 'var(--red-light)', label: 'BLOCKED' },
  HUMAN_REVIEW: { icon: Clock, color: 'var(--purple)', bg: 'var(--purple-light)', label: 'HUMAN REVIEW' },
}

const TAGS = [...new Set(Object.values(SCENARIOS).map(s => s.tag))]

export default function SimulatePage() {
  const { hasPermission } = useAuth()
  const canRun = hasPermission('simulate:run') || hasPermission('*')

  const [scenario, setScenario] = useState('credit_clean')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [showExplain, setShowExplain] = useState(false)
  const [backendMode, setBackendMode] = useState(false) // true = persisted to DB
  const [propagated, setPropagated] = useState(false)
  const [history, setHistory] = useState([])
  const [tagFilter, setTagFilter] = useState('All')

  // Manual Entry States
  const [manualInput, setManualInput] = useState('')
  const [manualPrediction, setManualPrediction] = useState('')
  const [manualConfidence, setManualConfidence] = useState(0.95)

  // Sync manual states when switching to manual_llm
  useEffect(() => {
    if (scenario === 'manual_llm') {
      if (!manualInput) setManualInput(SCENARIOS.manual_llm.input_data.prompt)
      if (!manualPrediction) setManualPrediction(SCENARIOS.manual_llm.prediction.content)
    }
  }, [scenario])
  // Fetch available registered models for backend evaluation (optional/cleanup)
  useEffect(() => {
    // We can keep a ping to ensure backend is alive if we want, but auto-registration is handled by /simulate
  }, [])

  const sc = SCENARIOS[scenario]
  const filteredScenarios = Object.entries(SCENARIOS).filter(([, s]) => tagFilter === 'All' || s.tag === tagFilter)

  const run = useCallback(async () => {
    setLoading(true); setResult(null); setShowExplain(false); setPropagated(false)

    const isManual = scenario === 'manual_llm'
    const payload = {
      model_id: 'kavachx-manual-test',
      input_data: isManual ? { prompt: manualInput } : sc.input_data,
      prediction: isManual ? { label: 'MANUAL', content: manualPrediction } : sc.prediction,
      confidence: isManual ? manualConfidence : sc.confidence,
      context: sc.context,
    }

    let res = null
    let persisted = false

    try {
      // Always call /simulate — no auth required, auto-creates model, persists to DB
      const r = await governanceAPI.simulate(payload)
      const d = r.data
      res = {
        inference_id: d.inference_id,
        risk_score: d.risk_score,
        risk_level: d.risk_level?.value || d.risk_level,
        enforcement_decision: d.enforcement_decision?.value || d.enforcement_decision,
        fairness_flags: d.fairness_flags || [],
        policy_violations: d.policy_violations || [],
        explanation: d.explanation || {},
        processing_ms: d.processing_time_ms,
      }
      persisted = true
      // Notify other pages (AuditPage, Dashboards) about the new event
      window.dispatchEvent(new CustomEvent('kavachx:simulation-complete', { detail: res }))
    } catch {
      // Backend unavailable — fall back to local pipeline so UX never breaks
      res = runLocalPipeline(sc)
    }

    setResult(res)
    setBackendMode(persisted)
    if (persisted) setPropagated(true)

    setHistory(prev => [{
      id: res.inference_id, scenario: sc.label, tag: sc.tag, tagColor: sc.tagColor,
      decision: res.enforcement_decision, riskScore: res.risk_score,
      violations: res.policy_violations?.length || 0,
      ts: new Date(), persisted,
    }, ...prev].slice(0, 10))

    setLoading(false)
  }, [scenario, sc, manualInput, manualPrediction, manualConfidence])

  if (!canRun) return (
    <div className="role-denied">
      <div className="role-denied-icon"><Shield size={26} /></div>
      <div style={{ fontSize: 16, fontWeight: 700 }}>Simulation Restricted</div>
      <div style={{ fontSize: 13, color: 'var(--text-muted)', maxWidth: 340, lineHeight: 1.65 }}>Running simulations requires ML Engineer or Administrator role.</div>
    </div>
  )

  const dm = result && !result._error ? (DM[result.enforcement_decision] || DM.PASS) : null
  const riskPct = result ? (result.risk_score * 100).toFixed(1) : '0.0'
  const riskColor = result ? (result.risk_score > 0.75 ? 'var(--red)' : result.risk_score > 0.45 ? 'var(--amber)' : 'var(--green)') : 'var(--green)'
  const expectedDm = DM[sc.expectedDecision] || DM.PASS

  return (
    <div>
      <div className="page-header">
        <div className="page-eyebrow">Governance</div>
        <h1 className="page-title">Inference Simulator</h1>
        <p className="page-desc">
          Run governance scenarios against system policies. Every execution creates live governance events that are stored in the database and immediately reflected across Dashboards, Audit Logs, and Analytics.
        </p>
      </div>

      {/* Propagation banner */}
      {propagated && (
        <div className="alert alert-success mb-20 fade-up" style={{ fontSize: 12.5 }}>
          <Database size={14} style={{ flexShrink: 0 }} />
          <span>
            <strong>Data persisted to platform.</strong> Dashboards, Audit Logs, and Risk Trend charts will now reflect this governance event. Refresh any page to see live data.
          </span>
        </div>
      )}


      <div className="grid-1-2" style={{ alignItems: 'start' }}>
        {/* ── Left: Scenario picker ── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>


          {/* Tag filter pills */}
          <div className="filter-pills">
            {['All', ...TAGS].map(t => (
              <button key={t} className={`filter-pill ${tagFilter === t ? 'active' : ''}`} onClick={() => setTagFilter(t)} style={{ fontSize: 10.5 }}>{t}</button>
            ))}
          </div>

          {/* Scenario list */}
          <div className="card">
            <div className="card-header"><span className="card-title">Test Scenario</span><Zap size={13} style={{ color: 'var(--accent)', opacity: 0.8 }} /></div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 14, maxHeight: 380, overflowY: 'auto', paddingRight: 4 }}>
              {filteredScenarios.map(([key, s]) => {
                const active = scenario === key
                const expDm = DM[s.expectedDecision]
                return (
                  <button key={key} onClick={() => { setScenario(key); setResult(null) }}
                    style={{ textAlign: 'left', padding: '9px 12px', border: `1px solid ${active ? 'var(--accent)' : 'var(--border)'}`, borderRadius: 9, background: active ? 'var(--accent-light)' : 'var(--bg-elevated)', cursor: 'pointer', transition: 'all .12s', display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 10 }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 12.5, fontWeight: 600, color: active ? 'var(--accent)' : 'var(--text)', marginBottom: 1 }}>{s.label}</div>
                      <div style={{ fontSize: 10.5, color: 'var(--text-muted)', lineHeight: 1.4 }}>{s.desc}</div>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4, flexShrink: 0 }}>
                      <span style={{ fontSize: 9.5, fontWeight: 700, padding: '2px 6px', borderRadius: 8, background: active ? s.tagColor : s.tagBg, color: active ? '#fff' : s.tagColor, border: `1px solid ${s.tagColor}30` }}>{s.tag}</span>
                      {expDm && <span style={{ fontSize: 9, fontWeight: 700, color: expDm.color, opacity: 0.8 }}>→ {s.expectedDecision}</span>}
                    </div>
                  </button>
                )
              })}
            </div>

            <button className="btn btn-primary w-full" onClick={run} disabled={loading} style={{ justifyContent: 'center', padding: '10px 16px', fontSize: 13 }}>
              {loading
                ? <><span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} /> Running pipeline...</>
                : <><PlayCircle size={15} /> Run Evaluation</>
              }
            </button>
          </div>

          {/* Selected scenario info */}
          <div className="card" style={{ padding: '12px 14px' }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 8 }}>Policy References</div>
            {sc.policyRefs.map(ref => (
              <div key={ref} style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--accent)', background: 'var(--accent-light)', padding: '2px 7px', borderRadius: 4, marginBottom: 3, display: 'inline-block', marginRight: 4 }}>{ref}</div>
            ))}
            <div style={{ marginTop: 10, fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 4 }}>Expected Outcome</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              {expectedDm && <expectedDm.icon size={14} style={{ color: expectedDm.color }} />}
              <span style={{ fontSize: 12, fontWeight: 700, color: expectedDm?.color }}>{sc.expectedDecision}</span>
            </div>
          </div>

          {/* Input payload */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">{scenario === 'manual_llm' ? 'Edit Test Data' : 'Input Payload'}</span>
              <div style={{ display: 'flex', gap: 6 }}>
                {scenario === 'manual_llm' && (
                  <span style={{ fontSize: 9.5, fontWeight: 700, color: 'var(--cyan)', background: 'var(--cyan-light)', padding: '2px 7px', borderRadius: 4, display: 'flex', alignItems: 'center', gap: 4 }}>
                    <Shield size={10} /> LIVE SCAN
                  </span>
                )}
                <span style={{ fontSize: 9.5, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', background: 'var(--bg-elevated)', padding: '2px 7px', borderRadius: 4 }}>
                  {scenario === 'manual_llm' ? 'EDITABLE' : 'JSON'}
                </span>
              </div>
            </div>

            {scenario === 'manual_llm' ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <div>
                  <div style={{ fontSize: 10.5, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 5, textTransform: 'uppercase' }}>User Prompt (Input)</div>
                  <textarea
                    className="input-field"
                    style={{ minHeight: 80, fontSize: 11.5, width: '100%', resize: 'vertical', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, padding: '10px', color: 'var(--text-primary)' }}
                    value={manualInput}
                    onChange={(e) => setManualInput(e.target.value)}
                    placeholder="Paste your ChatGPT prompt here..."
                  />
                </div>
                <div>
                  <div style={{ fontSize: 10.5, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 5, textTransform: 'uppercase' }}>Model Response (Prediction)</div>
                  <textarea
                    className="input-field"
                    style={{ minHeight: 80, fontSize: 11.5, width: '100%', resize: 'vertical', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, padding: '10px', color: 'var(--text-primary)' }}
                    value={manualPrediction}
                    onChange={(e) => setManualPrediction(e.target.value)}
                    placeholder="Paste the AI's response here..."
                  />
                </div>
                <div>
                  <div style={{ fontSize: 10.5, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 5, textTransform: 'uppercase' }}>Confidence: {(manualConfidence * 100).toFixed(0)}%</div>
                  <input
                    type="range"
                    min="0"
                    max="1"
                    step="0.01"
                    value={manualConfidence}
                    onChange={(e) => setManualConfidence(parseFloat(e.target.value))}
                    style={{ width: '100%', accentColor: 'var(--accent)' }}
                  />
                </div>
              </div>
            ) : (
              <pre style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', background: 'var(--bg-elevated)', padding: '10px 12px', borderRadius: 7, overflow: 'auto', maxHeight: 160, lineHeight: 1.7, margin: 0, border: '1px solid var(--border)' }}>
                {JSON.stringify({ input_data: sc.input_data, confidence: sc.confidence, context: sc.context }, null, 2)}
              </pre>
            )}
          </div>
        </div>

        {/* ── Right: Results ── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {!result && !loading && (
            <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 380, gap: 14, border: '2px dashed var(--border)', background: 'transparent', boxShadow: 'none' }}>
              <div style={{ width: 54, height: 54, borderRadius: 14, background: 'var(--accent-light)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <BarChart2 size={26} style={{ color: 'var(--accent)', opacity: 0.6 }} />
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text-dim)', marginBottom: 5 }}>Ready to evaluate</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.65 }}>Select a scenario and press<br /><strong style={{ color: 'var(--accent)' }}>Run Evaluation</strong></div>
              </div>
            </div>
          )}

          {loading && (
            <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 380, gap: 20 }}>
              <div style={{ position: 'relative' }}>
                <div className="spinner" style={{ width: 40, height: 40, borderWidth: 3 }} />
                <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <Shield size={14} style={{ color: 'var(--accent)' }} />
                </div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text-dim)', marginBottom: 4 }}>Running governance pipeline</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Evaluating fairness, policy compliance &amp; risk...</div>
              </div>
            </div>
          )}

          {result && dm && (
            <div className="card fade-up">
              {/* Mode badge */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 10 }}>
                {backendMode
                  ? <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10.5, fontWeight: 700, color: 'var(--green)', background: 'var(--green-light)', padding: '2px 9px', borderRadius: 20, border: '1px solid rgba(5,150,105,.15)' }}><Database size={10} /> Persisted to Platform</span>
                  : <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10.5, fontWeight: 600, color: 'var(--text-muted)', background: 'var(--bg-elevated)', padding: '2px 9px', borderRadius: 20, border: '1px solid var(--border)' }}><Activity size={10} /> Local Simulation</span>
                }
              </div>

              {/* Decision header */}
              <div style={{ background: dm.bg, border: `1px solid ${dm.color}25`, borderRadius: 10, padding: '16px 18px', marginBottom: 18, display: 'flex', alignItems: 'center', gap: 14 }}>
                <div style={{ width: 44, height: 44, borderRadius: 11, background: `${dm.color}18`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <dm.icon size={22} style={{ color: dm.color }} />
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 20, fontWeight: 800, letterSpacing: '-0.03em', color: dm.color, lineHeight: 1 }}>{dm.label}</div>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginTop: 3 }}>
                    Risk level: <strong style={{ textTransform: 'capitalize' }}>{result.risk_level}</strong>
                    <span style={{ margin: '0 6px', opacity: 0.4 }}>·</span>
                    ID: <code style={{ fontFamily: 'var(--font-mono)', fontSize: 10.5 }}>{result.inference_id}</code>
                  </div>
                </div>
                <div style={{ textAlign: 'right', flexShrink: 0 }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2 }}>Processed in</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 700, color: 'var(--text)' }}>{result.processing_ms}ms</div>
                </div>
              </div>

              {/* Risk bar */}
              <div style={{ marginBottom: 18 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <span style={{ fontSize: 11.5, fontWeight: 700, color: 'var(--text-dim)' }}>Composite Risk Score</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 700, color: riskColor }}>{riskPct}%</span>
                </div>
                <div className="risk-bar" style={{ height: 8, borderRadius: 4 }}>
                  <div className="risk-fill" style={{ width: `${riskPct}%`, background: riskColor, borderRadius: 4 }} />
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4, fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  <span>LOW</span><span>MEDIUM</span><span>HIGH</span><span>CRITICAL</span>
                </div>
              </div>

              {/* Stats */}
              <div className="grid-3" style={{ marginBottom: 18 }}>
                {[
                  { label: 'Fairness Flags', value: result.fairness_flags?.length ?? 0, color: result.fairness_flags?.length ? 'var(--amber)' : 'var(--green)' },
                  { label: 'Policy Violations', value: result.policy_violations?.length ?? 0, color: result.policy_violations?.length ? 'var(--red)' : 'var(--green)' },
                  { label: 'Confidence', value: `${(sc.confidence * 100).toFixed(0)}%`, color: sc.confidence < 0.55 ? 'var(--red)' : sc.confidence < 0.70 ? 'var(--amber)' : 'var(--green)' },
                ].map(s => (
                  <div key={s.label} style={{ background: 'var(--bg-elevated)', borderRadius: 9, padding: '10px 12px', textAlign: 'center', border: '1px solid var(--border)' }}>
                    <div style={{ fontSize: 18, fontWeight: 800, color: s.color, fontFamily: 'var(--font-mono)', lineHeight: 1 }}>{s.value}</div>
                    <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 5 }}>{s.label}</div>
                  </div>
                ))}
              </div>

              <div className="divider" />

              {/* Fairness flags */}
              {result.fairness_flags?.length > 0 && (
                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontSize: 10.5, fontWeight: 700, letterSpacing: '.07em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 7 }}>Fairness Flags</div>
                  {result.fairness_flags.map((f, i) => (
                    <div key={i} className="alert alert-warn" style={{ marginBottom: 5 }}>
                      <AlertTriangle size={13} style={{ flexShrink: 0, marginTop: 1 }} />
                      <div>
                        <strong>{(f.metric || '').replace(/_/g, ' ')}</strong>
                        {' — '}{f.group_a} vs {f.group_b}:{' '}
                        <code style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>+{(f.disparity * 100).toFixed(1)}%</code> disparity
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Policy violations */}
              {result.policy_violations?.length > 0 && (
                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontSize: 10.5, fontWeight: 700, letterSpacing: '.07em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 7 }}>Policy Violations ({result.policy_violations.length})</div>
                  {result.policy_violations.map((v, i) => (
                    <div key={i} style={{ padding: '9px 12px', background: 'var(--red-light)', borderRadius: 7, marginBottom: 5, fontSize: 12, color: 'var(--red)', border: '1px solid rgba(220,38,38,0.12)', display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                      <XCircle size={13} style={{ flexShrink: 0, marginTop: 1 }} />
                      <div>
                        <strong>{v.policy_name}</strong>
                        {v.rule_id && <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', marginLeft: 6, opacity: 0.7 }}>({v.rule_id})</span>}
                        {v.message && <div style={{ fontWeight: 400, marginTop: 1, opacity: 0.85 }}>{v.message}</div>}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Explainability */}
              {result.explanation && (
                <div>
                  <button className="btn btn-ghost btn-sm" onClick={() => setShowExplain(v => !v)} style={{ marginBottom: 7, fontSize: 11.5 }}>
                    {showExplain ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                    Feature Importance &amp; Explanation
                  </button>
                  {showExplain && (
                    <div className="code-block">
                      <pre style={{ margin: 0, fontSize: 11, lineHeight: 1.7 }}>
                        {JSON.stringify({ summary: result.explanation.summary, confidence: result.explanation.confidence, top_features: result.explanation.top_features }, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              )}

              {/* Re-run */}
              <div style={{ marginTop: 16, paddingTop: 14, borderTop: '1px solid var(--border)', display: 'flex', gap: 8 }}>
                <button className="btn btn-secondary btn-sm" onClick={run}><RefreshCw size={12} /> Run Again</button>
                <button className="btn btn-ghost btn-sm" onClick={() => { setResult(null); setShowExplain(false); setPropagated(false) }}>Clear</button>
              </div>
            </div>
          )}

          {/* Session history */}
          {history.length > 0 && (
            <div className="card">
              <div className="card-header">
                <span className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 6 }}><History size={13} /> Session History</span>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{history.length} run{history.length > 1 ? 's' : ''}</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                {history.map(h => {
                  const hdm = DM[h.decision] || DM.PASS
                  return (
                    <div key={h.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '7px 10px', background: 'var(--bg-elevated)', borderRadius: 7, border: '1px solid var(--border)' }}>
                      <hdm.icon size={13} style={{ color: hdm.color, flexShrink: 0 }} />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.scenario}</div>
                        <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>Risk {(h.riskScore * 100).toFixed(0)}% · {h.violations} violation{h.violations !== 1 ? 's' : ''}</div>
                      </div>
                      <div style={{ display: 'flex', flex: 'column', alignItems: 'flex-end', gap: 3 }}>
                        <span style={{ fontSize: 10.5, fontWeight: 700, color: hdm.color }}>{h.decision}</span>
                        {h.persisted && <span style={{ fontSize: 9, color: 'var(--green)' }}>● DB</span>}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
