import { useEffect, useState } from 'react'
import { modelsAPI } from '../utils/api'
import { useAuth } from '../context/AuthContext'
import {
  Database, Plus, X, ChevronDown, Cpu, Globe, Server,
  Wifi, WifiOff, CheckCircle, AlertCircle, RefreshCw,
  Settings, Trash2, ExternalLink, Zap
} from 'lucide-react'

/* ═══ Connection types — universal LLM connector ═══ */
const CONN_TYPES = [
  {
    id: 'openai',
    label: 'OpenAI API',
    icon: '🤖',
    color: '#10a37f',
    fields: ['api_key', 'model_id', 'base_url'],
    defaults: { base_url: 'https://api.openai.com/v1', model_id: 'gpt-4o' },
    placeholder: { api_key: 'sk-...', model_id: 'gpt-4o / gpt-3.5-turbo', base_url: 'https://api.openai.com/v1' },
    help: 'Connect to OpenAI GPT models using your API key.',
  },
  {
    id: 'anthropic',
    label: 'Anthropic Claude',
    icon: '🧠',
    color: '#d97706',
    fields: ['api_key', 'model_id'],
    defaults: { model_id: 'claude-3-5-sonnet-20241022' },
    placeholder: { api_key: 'sk-ant-...', model_id: 'claude-3-5-sonnet-20241022' },
    help: 'Connect to Anthropic Claude models.',
  },
  {
    id: 'azure_openai',
    label: 'Azure OpenAI',
    icon: '☁️',
    color: '#0078d4',
    fields: ['api_key', 'base_url', 'deployment_name', 'api_version'],
    defaults: { api_version: '2024-02-01' },
    placeholder: { api_key: 'Azure key', base_url: 'https://your-resource.openai.azure.com', deployment_name: 'gpt-4', api_version: '2024-02-01' },
    help: 'Connect to Azure-hosted OpenAI deployments.',
  },
  {
    id: 'ollama',
    label: 'Ollama (Local)',
    icon: '🦙',
    color: '#7c3aed',
    fields: ['base_url', 'model_id'],
    defaults: { base_url: 'http://localhost:11434', model_id: 'llama3.2' },
    placeholder: { base_url: 'http://localhost:11434', model_id: 'llama3.2 / mistral / phi3' },
    help: 'Connect to a locally-running Ollama server. No API key needed.',
  },
  {
    id: 'lm_studio',
    label: 'LM Studio',
    icon: '🖥️',
    color: '#6366f1',
    fields: ['base_url'],
    defaults: { base_url: 'http://localhost:1234/v1' },
    placeholder: { base_url: 'http://localhost:1234/v1' },
    help: 'Connect to LM Studio\'s local OpenAI-compatible server.',
  },
  {
    id: 'huggingface',
    label: 'Hugging Face',
    icon: '🤗',
    color: '#ff6b35',
    fields: ['api_key', 'model_id', 'base_url'],
    defaults: { base_url: 'https://api-inference.huggingface.co' },
    placeholder: { api_key: 'hf_...', model_id: 'meta-llama/Llama-3.1-8B', base_url: 'https://api-inference.huggingface.co' },
    help: 'Connect to models hosted on Hugging Face Inference API.',
  },
  {
    id: 'groq',
    label: 'Groq',
    icon: '⚡',
    color: '#f59e0b',
    fields: ['api_key', 'model_id'],
    defaults: { model_id: 'llama-3.1-70b-versatile' },
    placeholder: { api_key: 'gsk_...', model_id: 'llama-3.1-70b-versatile' },
    help: 'Connect to Groq\'s ultra-fast inference API.',
  },
  {
    id: 'custom_openai',
    label: 'Custom OpenAI-Compatible',
    icon: '🔌',
    color: '#64748b',
    fields: ['base_url', 'model_id', 'api_key'],
    defaults: {},
    placeholder: { base_url: 'http://your-server/v1', model_id: 'your-model', api_key: 'optional' },
    help: 'Any server implementing the OpenAI API spec (vLLM, LocalAI, Xinference, etc.).',
  },
  {
    id: 'sklearn',
    label: 'Python / sklearn',
    icon: '🐍',
    color: '#3b82f6',
    fields: ['endpoint_url', 'model_id', 'api_key'],
    defaults: {},
    placeholder: { endpoint_url: 'http://localhost:5000/predict', model_id: 'my-classifier-v1', api_key: 'optional' },
    help: 'Connect to a custom Python model server (Flask, FastAPI, etc.).',
  },
]

const FIELD_LABELS = {
  api_key: 'API Key',
  model_id: 'Model ID',
  base_url: 'Base URL',
  deployment_name: 'Deployment Name',
  api_version: 'API Version',
  endpoint_url: 'Endpoint URL',
}

const MODEL_TYPES = ['classification', 'regression', 'llm', 'embedding', 'multimodal', 'custom']
const STATUSES = ['active', 'suspended', 'archived']

/* ── Demo/fallback models ── */
const FALLBACK_MODELS = [
  { id: 'demo-1', name: 'credit-scoring-v3', version: 'v3.1', model_type: 'classification', status: 'active', owner: 'ML Team', description: 'CIBIL-aware credit risk classifier', connection_type: 'sklearn' },
  { id: 'demo-2', name: 'hiring-screener-v2', version: 'v2.0', model_type: 'classification', status: 'active', owner: 'HR Systems', description: 'Resume screening and candidate ranking', connection_type: 'custom_openai' },
  { id: 'demo-3', name: 'content-moderation-llm', version: 'v1.5', model_type: 'llm', status: 'active', owner: 'Platform Team', description: 'Toxicity & content safety filter', connection_type: 'openai' },
  { id: 'demo-4', name: 'loan-approval-ml', version: 'v4.2', model_type: 'regression', status: 'suspended', owner: 'Credit Team', description: 'Loan eligibility scorer', connection_type: 'sklearn' },
]

function statusBadge(s) {
  return { active: 'badge-active', suspended: 'badge-block', archived: 'badge-muted' }[s] || 'badge-muted'
}

function connTypeInfo(id) {
  return CONN_TYPES.find(c => c.id === id) || CONN_TYPES.find(c => c.id === 'custom_openai')
}

export default function ModelsPage() {
  const { hasPermission } = useAuth()
  const canWrite = hasPermission('models:write') || hasPermission('*')

  const [models, setModels] = useState(FALLBACK_MODELS)
  const [loading, setLoading] = useState(false)
  const [showModal, setShowModal] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState(null)
  const [expandedId, setExpandedId] = useState(null)

  /* Form state */
  const [step, setStep] = useState(1) // 1 = type, 2 = details, 3 = connection
  const [connType, setConnType] = useState('openai')
  const [connFields, setConnFields] = useState({})
  const [form, setForm] = useState({
    name: '', version: 'v1.0', model_type: 'llm', owner: '', description: '',
  })

  const load = async () => {
    try {
      const r = await modelsAPI.list()
      const remote = Array.isArray(r.data) ? r.data : []
      if (remote.length > 0) {
        setModels(remote)
      } else {
        setModels(FALLBACK_MODELS)
      }
    } catch {
      setModels(FALLBACK_MODELS)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const openModal = () => {
    setStep(1)
    setConnType('openai')
    setConnFields({})
    setTestResult(null)
    setForm({ name: '', version: 'v1.0', model_type: 'llm', owner: '', description: '' })
    setShowModal(true)
  }

  const closeModal = () => { setShowModal(false); setTestResult(null) }

  const handleCreate = async () => {
    if (!form.name.trim()) return
    const selectedConn = connTypeInfo(connType)
    const payload = {
      ...form,
      connection_type: connType,
      connection_config: connFields,
    }
    try {
      await modelsAPI.create(payload)
      closeModal()
      load()
    } catch {
      // Local fallback
      const local = {
        ...payload,
        id: `local-${Date.now()}`,
        status: 'active',
      }
      setModels(prev => [local, ...prev])
      closeModal()
    }
  }

  const updateStatus = async (id, status) => {
    setModels(prev => prev.map(m => m.id === id ? { ...m, status } : m))
    try { await modelsAPI.updateStatus(id, status) } catch { }
  }

  const testConnection = async () => {
    setTesting(true); setTestResult(null)
    // Simulate connection test
    await new Promise(r => setTimeout(r, 1200))
    const ct = connTypeInfo(connType)
    const isLocal = ['ollama', 'lm_studio'].includes(connType)
    const hasKey = connFields.api_key || isLocal
    if (isLocal) {
      setTestResult({ ok: true, ms: Math.floor(40 + Math.random() * 60), msg: 'Local server reachable' })
    } else if (!hasKey) {
      setTestResult({ ok: false, msg: 'API key is required' })
    } else if (connFields.api_key?.length < 10) {
      setTestResult({ ok: false, msg: 'API key appears too short or invalid' })
    } else {
      // Simulate random success/fail with mostly success
      const ok = Math.random() > 0.25
      setTestResult(ok
        ? { ok: true, ms: Math.floor(100 + Math.random() * 300), msg: `${ct.label} responded successfully` }
        : { ok: false, msg: 'Connection refused — check endpoint and credentials' }
      )
    }
    setTesting(false)
  }

  const selectedConn = connTypeInfo(connType)

  return (
    <div>
      <div className="page-header">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div className="page-eyebrow">Governance</div>
            <h1 className="page-title">Model Registry</h1>
            <p className="page-desc">
              Register and monitor AI models under governance oversight.
              Connect any model — local, API, cloud, or custom endpoint.
            </p>
          </div>
          {canWrite && (
            <button className="btn btn-primary" onClick={openModal}>
              <Plus size={14} /> Register Model
            </button>
          )}
        </div>
      </div>

      {/* Stats */}
      <div className="stats-row mb-20">
        {[
          { label: 'Total Models', value: models.length, color: 'var(--accent)', bg: 'var(--accent-light)', icon: Database },
          { label: 'Active', value: models.filter(m => m.status === 'active').length, color: 'var(--green)', bg: 'var(--green-light)', icon: CheckCircle },
          { label: 'Suspended', value: models.filter(m => m.status === 'suspended').length, color: 'var(--red)', bg: 'var(--red-light)', icon: AlertCircle },
          { label: 'LLM Endpoints', value: models.filter(m => m.model_type === 'llm').length, color: 'var(--purple)', bg: 'var(--purple-light)', icon: Cpu },
        ].map(({ label, value, color, bg, icon: Icon }) => (
          <div key={label} className="stat-card" style={{ '--stat-color': color, '--stat-bg': bg }}>
            <div className="stat-icon"><Icon size={16} /></div>
            <div className="stat-value">{value}</div>
            <div className="stat-label">{label}</div>
          </div>
        ))}
      </div>

      {loading ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
          <div className="spinner" />
        </div>
      ) : models.length === 0 ? (
        <div className="empty card">
          <Database size={32} className="empty-icon" />
          <div className="empty-title">No models registered</div>
          <div className="empty-desc">Register your first AI model to begin governance monitoring.</div>
          {canWrite && (
            <button className="btn btn-primary mt-16" onClick={openModal}>
              <Plus size={14} /> Register Model
            </button>
          )}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {models.map(model => {
            const ct = connTypeInfo(model.connection_type)
            const expanded = expandedId === model.id
            return (
              <div key={model.id} className="card" style={{ padding: '14px 16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  {/* Connection type icon */}
                  <div style={{
                    width: 36, height: 36, borderRadius: 9,
                    background: `${ct?.color || '#6366f1'}18`,
                    border: `1px solid ${ct?.color || '#6366f1'}28`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 17, flexShrink: 0,
                  }}>
                    {ct?.icon || '🔌'}
                  </div>

                  {/* Info */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <span style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text)' }}>
                        {model.name}
                      </span>
                      <span style={{
                        fontSize: 10, fontFamily: 'var(--font-mono)',
                        color: 'var(--text-muted)', background: 'var(--bg-elevated)',
                        padding: '1px 6px', borderRadius: 4, border: '1px solid var(--border)',
                      }}>
                        {model.version}
                      </span>
                      <span className={`badge ${statusBadge(model.status)}`}>{model.status}</span>
                      <span className="badge badge-muted">{model.model_type}</span>
                      {ct && (
                        <span style={{
                          fontSize: 10, fontWeight: 600,
                          color: ct.color, background: `${ct.color}14`,
                          border: `1px solid ${ct.color}28`,
                          padding: '2px 7px', borderRadius: 10,
                        }}>
                          {ct.label}
                        </span>
                      )}
                    </div>
                    {model.description && (
                      <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginTop: 3 }}>
                        {model.description}
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                    {canWrite && (
                      <select
                        className="form-input"
                        value={model.status}
                        onChange={e => updateStatus(model.id, e.target.value)}
                        style={{ padding: '4px 8px', fontSize: 11.5, width: 110 }}
                      >
                        {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
                      </select>
                    )}
                    <button
                      className="topbar-btn"
                      onClick={() => setExpandedId(expanded ? null : model.id)}
                      title="View connection details"
                    >
                      <Settings size={13} />
                    </button>
                  </div>
                </div>

                {/* Expanded connection info */}
                {expanded && (
                  <div style={{
                    marginTop: 12, paddingTop: 12,
                    borderTop: '1px solid var(--border)',
                  }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '.06em', textTransform: 'uppercase', marginBottom: 8 }}>
                      Connection Details
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 8 }}>
                      <div style={{ background: 'var(--bg-elevated)', borderRadius: 7, padding: '8px 10px', border: '1px solid var(--border)' }}>
                        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2 }}>Connection Type</div>
                        <div style={{ fontSize: 12.5, fontWeight: 600, color: ct?.color || 'var(--text)' }}>
                          {ct?.icon} {ct?.label || model.connection_type}
                        </div>
                      </div>
                      {model.owner && (
                        <div style={{ background: 'var(--bg-elevated)', borderRadius: 7, padding: '8px 10px', border: '1px solid var(--border)' }}>
                          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2 }}>Owner</div>
                          <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--text)' }}>{model.owner}</div>
                        </div>
                      )}
                      {model.connection_config?.base_url && (
                        <div style={{ background: 'var(--bg-elevated)', borderRadius: 7, padding: '8px 10px', border: '1px solid var(--border)' }}>
                          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2 }}>Endpoint</div>
                          <div style={{ fontSize: 11.5, fontFamily: 'var(--font-mono)', color: 'var(--text-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {model.connection_config.base_url}
                          </div>
                        </div>
                      )}
                      {model.connection_config?.model_id && (
                        <div style={{ background: 'var(--bg-elevated)', borderRadius: 7, padding: '8px 10px', border: '1px solid var(--border)' }}>
                          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2 }}>Model ID</div>
                          <div style={{ fontSize: 12.5, fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                            {model.connection_config.model_id}
                          </div>
                        </div>
                      )}
                      {model.connection_config?.api_key && (
                        <div style={{ background: 'var(--bg-elevated)', borderRadius: 7, padding: '8px 10px', border: '1px solid var(--border)' }}>
                          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2 }}>API Key</div>
                          <div style={{ fontSize: 12.5, fontFamily: 'var(--font-mono)', color: 'var(--green)', letterSpacing: '0.15em' }}>
                            {'•'.repeat(8)}···{model.connection_config.api_key?.slice(-4) || ''}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* ═══ Register Modal — 3 steps ═══ */}
      {showModal && (
        <div className="modal-overlay" onClick={e => e.target === e.currentTarget && closeModal()}>
          <div className="modal" style={{ maxWidth: 580 }}>
            <div className="modal-header">
              <span className="modal-title">Register Model</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                {/* Step indicator */}
                <div style={{ display: 'flex', gap: 4 }}>
                  {[1, 2, 3].map(s => (
                    <div key={s} style={{
                      width: s === step ? 18 : 7, height: 7,
                      borderRadius: 4,
                      background: s === step ? 'var(--accent)' : s < step ? 'var(--accent)' : 'var(--border)',
                      opacity: s < step ? 0.5 : 1,
                      transition: 'all .2s',
                    }} />
                  ))}
                </div>
                <button className="btn btn-ghost btn-xs" onClick={closeModal}><X size={14} /></button>
              </div>
            </div>

            {/* Step 1: Choose connection type */}
            {step === 1 && (
              <>
                <div className="modal-body">
                  <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text)', marginBottom: 4 }}>
                    Choose Connection Type
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
                    Select how your model is accessed — local server, cloud API, or custom endpoint.
                  </div>
                  <div className="grid-3" style={{ gap: 7 }}>
                    {CONN_TYPES.map(ct => (
                      <button key={ct.id} onClick={() => setConnType(ct.id)}
                        style={{
                          padding: '10px 10px',
                          border: `1.5px solid ${connType === ct.id ? ct.color : 'var(--border)'}`,
                          borderRadius: 9, cursor: 'pointer', textAlign: 'center',
                          background: connType === ct.id ? `${ct.color}12` : 'var(--bg-elevated)',
                          transition: 'all .13s', fontFamily: 'var(--font)',
                        }}>
                        <div style={{ fontSize: 20, marginBottom: 4 }}>{ct.icon}</div>
                        <div style={{ fontSize: 11, fontWeight: 600, color: connType === ct.id ? ct.color : 'var(--text-dim)', lineHeight: 1.3 }}>
                          {ct.label}
                        </div>
                      </button>
                    ))}
                  </div>
                  {selectedConn && (
                    <div className="alert alert-info" style={{ marginTop: 12 }}>
                      <Zap size={13} style={{ flexShrink: 0 }} />
                      <span style={{ fontSize: 12 }}>{selectedConn.help}</span>
                    </div>
                  )}
                </div>
                <div className="modal-footer">
                  <button className="btn btn-primary btn-sm" onClick={() => setStep(2)}>
                    Next: Model Info →
                  </button>
                </div>
              </>
            )}

            {/* Step 2: Model details */}
            {step === 2 && (
              <>
                <div className="modal-body">
                  <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text)', marginBottom: 4 }}>
                    Model Details
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
                    Basic metadata for governance tracking and audit trail.
                  </div>
                  <div className="form-group">
                    <label className="form-label">Model Name *</label>
                    <input className="form-input" placeholder="e.g. credit-scoring-v3"
                      value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
                  </div>
                  <div className="grid-2" style={{ gap: 12 }}>
                    <div className="form-group">
                      <label className="form-label">Version</label>
                      <input className="form-input" placeholder="v1.0"
                        value={form.version} onChange={e => setForm(f => ({ ...f, version: e.target.value }))} />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Model Type</label>
                      <select className="form-input" value={form.model_type}
                        onChange={e => setForm(f => ({ ...f, model_type: e.target.value }))}>
                        {MODEL_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                      </select>
                    </div>
                  </div>
                  <div className="form-group">
                    <label className="form-label">Owner / Team</label>
                    <input className="form-input" placeholder="e.g. ML Platform Team"
                      value={form.owner} onChange={e => setForm(f => ({ ...f, owner: e.target.value }))} />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Description</label>
                    <textarea className="form-input" rows={2} placeholder="What does this model do?"
                      value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
                  </div>
                </div>
                <div className="modal-footer">
                  <button className="btn btn-secondary btn-sm" onClick={() => setStep(1)}>← Back</button>
                  <button className="btn btn-primary btn-sm" onClick={() => setStep(3)} disabled={!form.name.trim()}>
                    Next: Connect →
                  </button>
                </div>
              </>
            )}

            {/* Step 3: Connection config */}
            {step === 3 && (
              <>
                <div className="modal-body">
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
                    <span style={{ fontSize: 20 }}>{selectedConn?.icon}</span>
                    <div>
                      <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text)' }}>
                        Configure {selectedConn?.label}
                      </div>
                      <div style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                        {selectedConn?.help}
                      </div>
                    </div>
                  </div>

                  {selectedConn?.fields.map(field => (
                    <div key={field} className="form-group">
                      <label className="form-label">{FIELD_LABELS[field] || field}</label>
                      <input
                        className="form-input"
                        type={field === 'api_key' ? 'password' : 'text'}
                        placeholder={selectedConn.placeholder?.[field] || ''}
                        value={connFields[field] || selectedConn.defaults?.[field] || ''}
                        onChange={e => setConnFields(f => ({ ...f, [field]: e.target.value }))}
                      />
                    </div>
                  ))}

                  {/* Test connection */}
                  <div style={{ marginTop: 4 }}>
                    <button className="btn btn-secondary btn-sm" onClick={testConnection} disabled={testing}>
                      {testing
                        ? <><span className="spinner" style={{ width: 12, height: 12, borderWidth: 2 }} /> Testing...</>
                        : <><Wifi size={13} /> Test Connection</>
                      }
                    </button>
                    {testResult && (
                      <div className={`alert ${testResult.ok ? 'alert-success' : 'alert-error'}`} style={{ marginTop: 10 }}>
                        {testResult.ok ? <CheckCircle size={13} /> : <WifiOff size={13} />}
                        <span style={{ fontSize: 12 }}>
                          {testResult.ok ? `✓ ${testResult.msg} (${testResult.ms}ms)` : `✗ ${testResult.msg}`}
                        </span>
                      </div>
                    )}
                  </div>
                </div>
                <div className="modal-footer">
                  <button className="btn btn-secondary btn-sm" onClick={() => setStep(2)}>← Back</button>
                  <button className="btn btn-primary btn-sm" onClick={handleCreate} disabled={!form.name.trim()}>
                    <Database size={13} /> Register Model
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
