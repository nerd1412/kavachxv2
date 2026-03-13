import { useState } from 'react'
import { GitBranch, Database, Cpu, FlaskConical, ChevronRight, Info } from 'lucide-react'

const EXAMPLE_DAG = [
  { id: 'ds1', type: 'dataset', label: 'loan_applications_2024_raw', meta: { source: 'HDFC Bank DB', consent: '98.4%', dpdp: 'contract_performance', actor: 'data-team@org' } },
  { id: 'pp1', type: 'preprocessing', label: 'clean_v3', meta: { ops: ['null_imputation', 'outlier_removal', 'feature_encoding'], bias_delta: '+0.002', actor: 'ml-engineer@org', script_hash: 'sha256:a3f9c2...' } },
  { id: 'tr1', type: 'training', label: 'xgb_credit_v7', meta: { framework: 'XGBoost', epochs: 150, accuracy: '87.3%', fairness_score: '0.82', actor: 'ml-engineer@org' } },
  { id: 'mv1', type: 'model_version', label: 'credit-scoring v3.1', meta: { status: 'active', approved_by: 'compliance@org', deployed: '2024-04-01' } },
  { id: 'inf1', type: 'inference', label: 'production_batch_2024Q2', meta: { count: '142,000 inferences', avg_confidence: '0.79', anomalies: '0.3%' } },
]

const NODE_STYLES = {
  dataset: { color: 'var(--cyan)', bg: 'var(--cyan-light)', icon: Database },
  preprocessing: { color: 'var(--purple)', bg: 'var(--purple-light)', icon: FlaskConical },
  training: { color: 'var(--amber)', bg: 'var(--amber-light)', icon: Cpu },
  model_version: { color: 'var(--accent)', bg: 'var(--accent-light)', icon: GitBranch },
  inference: { color: 'var(--green)', bg: 'var(--green-light)', icon: ChevronRight },
}

export default function LineagePage() {
  const [selected, setSelected] = useState(null)

  return (
    <div>
      <div className="page-header">
        <div className="page-eyebrow">Advanced</div>
        <h1 className="page-title">Data Lineage</h1>
        <p className="page-desc">Track complete provenance chain from raw dataset to live inference — required for EU AI Act Art. 10 & DPDP compliance</p>
      </div>

      <div className="alert alert-info mb-20">
        <Info size={16} />
        <span style={{ fontSize: 12 }}>
          <strong>Example lineage graph</strong> for credit-scoring-v3. In production, lineage is automatically captured as models and datasets are registered through KavachX.
        </span>
      </div>

      <div className="grid-2-1">
        {/* DAG visualization */}
        <div className="card">
          <div className="card-header"><span className="card-title">Provenance DAG</span><span style={{ fontSize: 11, color: 'var(--text-muted)' }}>credit-scoring-v3</span></div>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 0, padding: '8px 0' }}>
            {EXAMPLE_DAG.map((node, i) => {
              const style = NODE_STYLES[node.type]
              const Icon = style.icon
              return (
                <div key={node.id} style={{ width: '100%' }}>
                  <div
                    onClick={() => setSelected(selected?.id === node.id ? null : node)}
                    style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 16px', border: `1px solid ${selected?.id === node.id ? style.color : 'var(--border)'}`, borderRadius: 10, background: selected?.id === node.id ? style.bg : 'var(--bg-elevated)', cursor: 'pointer', transition: 'all .15s' }}>
                    <div style={{ width: 32, height: 32, borderRadius: 8, background: style.bg, border: `1px solid ${style.color}`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                      <Icon size={15} style={{ color: style.color }} />
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)' }}>{node.label}</div>
                      <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: style.color, textTransform: 'uppercase', letterSpacing: '.06em' }}>{node.type}</div>
                    </div>
                    <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{selected?.id === node.id ? '▲' : '▼'}</span>
                  </div>
                  {i < EXAMPLE_DAG.length - 1 && (
                    <div style={{ display: 'flex', justifyContent: 'center', padding: '4px 0' }}>
                      <div style={{ width: 2, height: 20, background: 'var(--border)', borderRadius: 1 }} />
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>

        {/* Details panel */}
        <div>
          {selected ? (
            <div className="card fade-up">
              <div className="card-header">
                <span className="card-title">Node Details</span>
                <span className="badge badge-info">{selected.type}</span>
              </div>
              <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 16 }}>{selected.label}</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {Object.entries(selected.meta).map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', flexDirection: 'column', gap: 2, padding: '8px 10px', background: 'var(--bg-elevated)', borderRadius: 6 }}>
                    <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '.06em' }}>{k}</span>
                    <span style={{ fontSize: 12.5, color: 'var(--text)', fontWeight: 500 }}>{Array.isArray(v) ? v.join(', ') : v}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 300, gap: 12, textAlign: 'center' }}>
              <GitBranch size={32} style={{ opacity: .2 }} />
              <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>Click a node to see provenance details</div>
            </div>
          )}

          <div className="card mt-16">
            <div className="card-header"><span className="card-title">Lineage Stats</span></div>
            {[
              { label: 'Total Nodes', value: EXAMPLE_DAG.length },
              { label: 'Data Sources', value: 1 },
              { label: 'Transformations', value: 2 },
              { label: 'Compliance Coverage', value: '98.4%' },
            ].map(({ label, value }) => (
              <div key={label} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{label}</span>
                <span style={{ fontSize: 13, fontWeight: 700 }}>{value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
