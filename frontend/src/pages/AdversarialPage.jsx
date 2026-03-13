import { useState } from 'react'
import { FlaskConical, PlayCircle, AlertTriangle, CheckCircle, XCircle, Info } from 'lucide-react'
import { governanceAPI, modelsAPI } from '../utils/api'
import { useEffect } from 'react'

const ATTACK_TYPES = [
  { id: 'prompt_injection', label: 'Prompt Injection', desc: 'Tests resistance to prompt hijacking attacks', severity: 'high' },
  { id: 'jailbreak', label: 'Jailbreak Attempt', desc: 'Tests safety guardrail bypasses', severity: 'critical' },
  { id: 'data_poisoning', label: 'Data Poisoning', desc: 'Tests robustness against adversarial inputs', severity: 'high' },
  { id: 'fairness_stress', label: 'Fairness Stress', desc: 'Tests demographic parity under edge cases', severity: 'medium' },
  { id: 'low_conf_flood', label: 'Low Confidence Flood', desc: 'Stress tests with systematically low confidence inputs', severity: 'medium' },
]

const MOCK_RESULTS = {
  prompt_injection: { passed: 8, failed: 2, score: 80, findings: ['PASS: Direct instruction override blocked', 'PASS: Role confusion attempt blocked', 'FAIL: Unicode obfuscation bypassed guard on 1 case', 'FAIL: Multi-turn context manipulation partially succeeded'] },
  jailbreak: { passed: 10, failed: 0, score: 100, findings: ['PASS: All 10 jailbreak patterns blocked by LLM Safety Guard'] },
  fairness_stress: { passed: 7, failed: 3, score: 70, findings: ['FAIL: Gender disparity +4.2% above threshold in 3 edge cases', 'PASS: Regional fairness within bounds', 'PASS: Caste-proxy detection triggered correctly'] },
  data_poisoning: { passed: 9, failed: 1, score: 90, findings: ['PASS: Outlier injection detected by risk scorer', 'FAIL: Subtle feature shift of 0.8σ not flagged'] },
  low_conf_flood: { passed: 10, failed: 0, score: 100, findings: ['PASS: All low-confidence requests routed to HUMAN_REVIEW as expected'] },
}

export default function AdversarialPage() {
  const [models, setModels] = useState([])
  const [modelId, setModelId] = useState('')
  const [selected, setSelected] = useState([])
  const [running, setRunning] = useState(false)
  const [results, setResults] = useState(null)

  useEffect(() => {
    modelsAPI.list().then(r => { const data = r.data || []; setModels(data); if (data[0]) setModelId(data[0].id) }).catch(() => { const fb = [{id:"demo-1",name:"credit-scoring-v3"},{id:"demo-3",name:"content-moderation-llm"}]; setModels(fb); setModelId(fb[0].id) })
  }, [])

  const toggle = (id) => setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id])

  const run = async () => {
    if (!selected.length || !modelId) return
    setRunning(true); setResults(null)
    await new Promise(r => setTimeout(r, 2000)) // simulate
    const r = {}
    selected.forEach(id => { r[id] = MOCK_RESULTS[id] || { passed: 5, failed: 5, score: 50, findings: ['Mock result'] } })
    setResults(r); setRunning(false)
  }

  const overallScore = results ? Math.round(Object.values(results).reduce((a, r) => a + r.score, 0) / Object.values(results).length) : null

  return (
    <div>
      <div className="page-header">
        <div className="page-eyebrow">Advanced</div>
        <h1 className="page-title">Adversarial Testing</h1>
        <p className="page-desc">Automated attack simulation to test model robustness, safety, and fairness under adversarial conditions</p>
      </div>

      <div className="alert alert-info mb-20">
        <Info size={16} />
        <span style={{ fontSize: 12 }}>This module simulates attacks against your governance-wrapped models. Results reflect governance layer effectiveness, not raw model vulnerabilities.</span>
      </div>

      <div className="grid-2-1">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Attack selection */}
          <div className="card">
            <div className="card-header"><span className="card-title">Attack Suite</span></div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {ATTACK_TYPES.map(at => {
                const sel = selected.includes(at.id)
                return (
                  <div key={at.id} onClick={() => toggle(at.id)}
                    style={{ padding: '12px 14px', border: `1px solid ${sel ? 'var(--accent)' : 'var(--border)'}`, borderRadius: 10, cursor: 'pointer', background: sel ? 'var(--accent-light)' : 'var(--bg-elevated)', transition: 'all .15s' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div style={{ width: 16, height: 16, borderRadius: 4, border: `2px solid ${sel ? 'var(--accent)' : 'var(--border)'}`, background: sel ? 'var(--accent)' : 'transparent', display: 'flex', alignItems: 'center', justifyContent: 'center', transition: 'all .15s' }}>
                          {sel && <CheckCircle size={10} style={{ color: '#fff' }} />}
                        </div>
                        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)' }}>{at.label}</span>
                      </div>
                      <span className={`badge badge-${at.severity === 'critical' ? 'block' : at.severity === 'high' ? 'alert' : 'medium'}`}>{at.severity}</span>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4, marginLeft: 24 }}>{at.desc}</div>
                  </div>
                )
              })}
            </div>
          </div>

          <div className="card">
            <div className="form-group mb-12">
              <label className="form-label">Target Model</label>
              <select className="form-input" value={modelId} onChange={e => setModelId(e.target.value)}>
                {models.map(m => <option key={m.id} value={m.id}>{m.name}</option>)}
              </select>
            </div>
            <button className="btn btn-primary w-full" onClick={run} disabled={running || !selected.length || !modelId} style={{ justifyContent: 'center' }}>
              {running ? <><span className="spinner" style={{ width: 16, height: 16 }} /> Running Tests...</> : <><FlaskConical size={15} /> Run Selected Tests ({selected.length})</>}
            </button>
          </div>
        </div>

        {/* Results */}
        <div>
          {!results && !running && (
            <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 300, gap: 12 }}>
              <FlaskConical size={32} style={{ opacity: .2 }} />
              <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>Select attacks and run tests</div>
            </div>
          )}
          {running && (
            <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 300, gap: 16 }}>
              <div className="spinner" style={{ width: 36, height: 36, borderWidth: 3 }} />
              <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>Executing adversarial test suite...</div>
            </div>
          )}
          {results && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {/* Overall score */}
              <div className="card fade-up" style={{ background: overallScore >= 80 ? 'var(--green-light)' : overallScore >= 60 ? 'var(--amber-light)' : 'var(--red-light)', border: `1px solid ${overallScore >= 80 ? 'var(--green)' : overallScore >= 60 ? 'var(--amber)' : 'var(--red)'}` }}>
                <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>Overall Governance Score</div>
                <div style={{ fontSize: 36, fontWeight: 800, fontFamily: 'var(--font-mono)' }}>{overallScore}%</div>
                <div style={{ fontSize: 12, opacity: .8 }}>{overallScore >= 80 ? 'Strong governance posture' : overallScore >= 60 ? 'Some gaps identified' : 'Critical vulnerabilities found'}</div>
              </div>

              {Object.entries(results).map(([id, res]) => {
                const at = ATTACK_TYPES.find(a => a.id === id)
                return (
                  <div key={id} className="card fade-up">
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                      <span style={{ fontWeight: 700 }}>{at?.label || id}</span>
                      <span style={{ fontSize: 18, fontWeight: 800, fontFamily: 'var(--font-mono)', color: res.score >= 80 ? 'var(--green)' : res.score >= 60 ? 'var(--amber)' : 'var(--red)' }}>{res.score}%</span>
                    </div>
                    <div style={{ display: 'flex', gap: 16, marginBottom: 10 }}>
                      <span style={{ fontSize: 12, color: 'var(--green)', display: 'flex', alignItems: 'center', gap: 4 }}><CheckCircle size={12} /> {res.passed} passed</span>
                      <span style={{ fontSize: 12, color: 'var(--red)', display: 'flex', alignItems: 'center', gap: 4 }}><XCircle size={12} /> {res.failed} failed</span>
                    </div>
                    {res.findings.map((f, i) => (
                      <div key={i} style={{ fontSize: 12, color: f.startsWith('FAIL') ? 'var(--red)' : 'var(--green)', padding: '4px 0', borderTop: i === 0 ? '1px solid var(--border)' : 'none', paddingTop: i === 0 ? 8 : 2 }}>
                        {f}
                      </div>
                    ))}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
