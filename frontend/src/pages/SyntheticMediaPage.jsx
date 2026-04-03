import { useState, useEffect, useRef, useCallback } from 'react'
import { Upload, Film, Image, Music, ShieldCheck, ShieldAlert, Download, Hash, AlertTriangle, CheckCircle, RefreshCw, FileSearch } from 'lucide-react'
import Card from '../components/shared/Card'
import { api } from '../utils/api'

// ── API helpers ───────────────────────────────────────────────────────────────
const syntheticAPI = {
  scan: (file) => {
    const form = new FormData()
    form.append('file', file)
    return api.post('/synthetic-shield/scan', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 120000,
    })
  },
  listScans: (limit = 20) => api.get(`/synthetic-shield/scans?limit=${limit}`),
}

// ── Helpers ───────────────────────────────────────────────────────────────────
const ACCEPT = 'image/*,video/mp4,video/webm,audio/mpeg,audio/wav,audio/ogg'

function formatBytes(b) {
  if (!b) return '—'
  if (b < 1024) return `${b} B`
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`
  return `${(b / 1048576).toFixed(1)} MB`
}

function fileIcon(type = '') {
  if (type.startsWith('video')) return <Film size={28} />
  if (type.startsWith('audio')) return <Music size={28} />
  return <Image size={28} />
}

function ActionBadge({ action }) {
  const map = {
    PASS:          { color: 'var(--green)',  icon: <CheckCircle size={13} />,   label: 'AUTHENTIC' },
    ALERT:         { color: 'var(--amber)',  icon: <AlertTriangle size={13} />, label: 'SUSPICIOUS' },
    BLOCK:         { color: 'var(--red)',    icon: <ShieldAlert size={13} />,   label: 'SYNTHETIC' },
    ESCALATE:      { color: 'var(--purple)', icon: <ShieldAlert size={13} />,   label: 'ESCALATED' },
    INCONCLUSIVE:  { color: 'var(--amber)',  icon: <AlertTriangle size={13} />, label: 'INCONCLUSIVE' },
  }
  const { color, icon, label } = map[action] || map.PASS
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '4px 10px', borderRadius: 20,
      background: `${color}22`, color,
      fontSize: 11, fontWeight: 700, letterSpacing: '0.06em',
    }}>
      {icon} {label}
    </span>
  )
}

function ConfidenceRing({ value = 0, synthetic = false, size = 108 }) {
  const pct = Math.round(value * 100)
  const color = synthetic
    ? (pct > 75 ? 'var(--red)' : pct > 45 ? 'var(--amber)' : 'var(--green)')
    : 'var(--green)'
  const half = size / 2
  const r = half - 10
  const circ = 2 * Math.PI * r
  const dash = circ * (pct / 100)
  return (
    <div style={{ position: 'relative', width: size, height: size, flexShrink: 0 }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={half} cy={half} r={r} fill="none" stroke="var(--border)" strokeWidth="8" />
        <circle
          cx={half} cy={half} r={r} fill="none"
          stroke={color} strokeWidth="8"
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 0.6s cubic-bezier(0.4,0,0.2,1)' }}
        />
      </svg>
      <div style={{
        position: 'absolute', inset: 0,
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
        gap: 1,
      }}>
        <span style={{ fontSize: size < 90 ? 18 : 22, fontWeight: 800, color, fontFeatureSettings: "'tnum' 1" }}>{pct}%</span>
        <span style={{ fontSize: 9, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em' }}>
          {synthetic ? 'AI Prob.' : 'Authentic'}
        </span>
      </div>
    </div>
  )
}

// ── Drop zone ─────────────────────────────────────────────────────────────────
function DropZone({ onFile, scanning }) {
  const [over, setOver] = useState(false)
  const inputRef = useRef(null)

  const handleDrop = useCallback((e) => {
    e.preventDefault()
    setOver(false)
    const f = e.dataTransfer?.files?.[0]
    if (f) onFile(f)
  }, [onFile])

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setOver(true) }}
      onDragLeave={() => setOver(false)}
      onDrop={handleDrop}
      onClick={() => !scanning && inputRef.current?.click()}
      style={{
        border: `2px dashed ${over ? 'var(--accent)' : 'var(--border)'}`,
        borderRadius: 'var(--radius-xl)',
        padding: '40px 24px',
        textAlign: 'center',
        cursor: scanning ? 'not-allowed' : 'pointer',
        transition: 'border-color var(--t-base), background var(--t-base)',
        background: over ? 'var(--accent-5)' : 'var(--bg-card)',
        opacity: scanning ? 0.6 : 1,
      }}
    >
      <input
        ref={inputRef} type="file" accept={ACCEPT} hidden
        onChange={(e) => { const f = e.target.files?.[0]; if (f) onFile(f) }}
      />
      <div style={{ color: over ? 'var(--accent)' : 'var(--text-muted)', marginBottom: 12, transition: 'color var(--t-base)' }}>
        {scanning
          ? <RefreshCw size={36} style={{ animation: 'spin 1s linear infinite' }} />
          : <Upload size={36} />}
      </div>
      <div style={{ fontWeight: 700, fontSize: 15, color: 'var(--text)', marginBottom: 6 }}>
        {scanning ? 'Scanning…' : 'Drop file or click to upload'}
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.7 }}>
        Supported: JPEG · PNG · MP4 · WebM · MP3 · WAV<br />
        Max 50 MB — BASCG P3 Synthetic Media Shield
      </div>
    </div>
  )
}

// ── Detection reasoning panel ─────────────────────────────────────────────────
const SIGNAL_LABELS = {
  // ── Metadata / provenance ───────────────────────────────────────────────
  ai_png_metadata:                    { label: 'AI generation parameters embedded in PNG metadata', severity: 'high',   category: 'metadata' },
  ai_byte_signature:                  { label: 'AI tool byte signature found in file body',         severity: 'high',   category: 'metadata' },
  ai_exif_software:                   { label: 'AI software identified in EXIF Software tag',       severity: 'high',   category: 'metadata' },
  ai_tool_in_exif:                    { label: 'AI tool referenced in EXIF metadata',               severity: 'high',   category: 'metadata' },
  known_ai_hash_match:                { label: 'Near-duplicate of a previously detected AI image',  severity: 'high',   category: 'metadata' },
  // ── Structural / origin ─────────────────────────────────────────────────
  ai_typical_dimensions:              { label: 'Dimensions match AI model standard output size',    severity: 'medium', category: 'structural' },
  ai_dimensions_no_embedded_metadata: { label: 'AI-typical dimensions with no origin metadata',     severity: 'medium', category: 'structural' },
  missing_camera_exif:                { label: 'No camera Make/Model in EXIF (expected for photos)','severity': 'medium', category: 'structural' },
  photographic_png_no_camera_origin:  { label: 'Photographic PNG — real cameras save as JPEG',     severity: 'medium', category: 'structural' },
  ffmpeg_encoder:                     { label: 'ffmpeg encoder tag (common deepfake pipeline)',     severity: 'medium', category: 'structural' },
  deepfake_typical_resolution:        { label: 'Square face-crop resolution typical of deepfakes', severity: 'medium', category: 'structural' },
  // ── Pixel-level forensics ───────────────────────────────────────────────
  anomalous_noise_floor:              { label: 'Abnormally low sensor noise (diffusion smooth)',    severity: 'medium', category: 'pixel_analysis' },
  smooth_texture:                     { label: 'Unnaturally smooth texture — diffusion artifact',   severity: 'low',    category: 'pixel_analysis' },
  ela_compression_ratio:              { label: 'High JPEG compression gain (first-time compression = AI)', severity: 'medium', category: 'pixel_analysis' },
  fft_grid_artifact:                  { label: 'Spectral grid artifact from VAE latent upsampling', severity: 'medium', category: 'pixel_analysis' },
  // ── Audio signals ───────────────────────────────────────────────────────
  very_short_audio:                   { label: 'Unusually short audio clip',                       severity: 'low',    category: 'other' },
  tts_sample_rate:                    { label: 'TTS-typical sample rate (16k / 22.05k / 24k Hz)',  severity: 'medium', category: 'other' },
  tts_mono_speech:                    { label: 'Mono 16-bit PCM at ≥16 kHz — canonical TTS format',severity: 'medium', category: 'other' },
  tts_silence_padding:                { label: 'High silence ratio — TTS boundary padding',        severity: 'medium', category: 'other' },
  tts_cbr_mp3:                        { label: 'CBR MP3 at 64/128 kbps without ID3 — TTS typical', severity: 'medium', category: 'other' },
  tts_abnormal_zcr:                   { label: 'Abnormal zero-crossing rate — TTS smooth pitch contour', severity: 'medium', category: 'other' },
  tts_uniform_amplitude:              { label: 'Unnaturally uniform amplitude — TTS normalisation artifact', severity: 'medium', category: 'other' },
  tts_flat_energy:                    { label: 'Flat short-term energy profile — TTS monotone synthesis', severity: 'medium', category: 'other' },
  // ── Video signals ───────────────────────────────────────────────────────
  suspiciously_small:                 { label: 'Unusually small video file for duration',           severity: 'low',    category: 'other' },
  video_frame_ai_signals:             { label: 'Embedded keyframe shows AI generation signals',     severity: 'high',   category: 'pixel_analysis' },
}

const SEVERITY_COLOR = { high: 'var(--red)', medium: 'var(--amber)', low: 'var(--text-muted)' }

const CATEGORY_META = {
  metadata:      { label: 'Metadata Analysis',    color: 'var(--red)' },
  structural:    { label: 'Structural Indicators', color: 'var(--amber)' },
  pixel_analysis:{ label: 'Pixel-level Analysis', color: 'var(--cyan, #06b6d4)' },
  other:         { label: 'Other Signals',         color: 'var(--text-muted)' },
}

function SignalBar({ sigKey, score }) {
  const info = SIGNAL_LABELS[sigKey] || { label: sigKey.replace(/_/g, ' '), severity: 'low', category: 'other' }
  const color = SEVERITY_COLOR[info.severity]
  const pct = Math.round(score * 100)
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <span style={{ flex: 1, fontSize: 11, color: 'var(--text-dim)', lineHeight: 1.4 }}>{info.label}</span>
      <div style={{ width: 56, height: 4, borderRadius: 2, background: 'var(--border)', flexShrink: 0 }}>
        <div style={{ width: `${pct}%`, height: '100%', borderRadius: 2, background: color, transition: 'width 0.4s' }} />
      </div>
      <span style={{ fontSize: 10, color, fontFamily: 'var(--font-mono)', minWidth: 30, textAlign: 'right' }}>{pct}%</span>
    </div>
  )
}

function DetectionReasoning({ raw }) {
  if (!raw) return null
  const classification = raw.classification
  const verdict = raw.verdict
  const signals = raw.signals || {}
  const hasSignals = Object.keys(signals).length > 0
  const categories = raw.signal_categories || {}
  const hasCategoryBreakdown = Object.keys(categories).length > 0

  // Group signals by category
  const grouped = {}
  Object.entries(signals).forEach(([key, score]) => {
    const cat = (SIGNAL_LABELS[key] || {}).category || 'other'
    if (!grouped[cat]) grouped[cat] = []
    grouped[cat].push([key, score])
  })
  const groupOrder = ['metadata', 'structural', 'pixel_analysis', 'other']

  return (
    <div style={{
      marginBottom: 16,
      borderRadius: 8,
      border: '1px solid var(--border)',
      overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{
        padding: '8px 12px',
        background: 'var(--bg-hover)',
        borderBottom: hasSignals ? '1px solid var(--border)' : 'none',
        display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap',
      }}>
        <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', flex: 1 }}>
          Detection Reasoning
        </span>
        {classification && (
          <span style={{
            fontSize: 10, padding: '2px 7px', borderRadius: 8, fontWeight: 600,
            background: classification === 'graphic_or_logo' ? 'var(--green-10, rgba(34,197,94,0.1))' : 'var(--accent-10)',
            color: classification === 'graphic_or_logo' ? 'var(--green)' : 'var(--accent)',
          }}>
            {classification === 'graphic_or_logo' ? 'Graphic / Logo' : 'Photograph'}
          </span>
        )}
        {raw.has_ai_metadata && (
          <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 8, fontWeight: 600, background: 'rgba(239,68,68,0.1)', color: 'var(--red)' }}>
            {raw.ai_tool_detected || 'AI tool detected'}
          </span>
        )}
        {raw.c2pa_provenance && (
          <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 8, fontWeight: 600, background: 'rgba(34,197,94,0.1)', color: 'var(--green)', display: 'inline-flex', alignItems: 'center', gap: 3 }}>
            <CheckCircle size={9} /> C2PA Signed
          </span>
        )}
        {raw.method && raw.method !== 'heuristic_image' && (
          <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 8, fontWeight: 600, background: 'var(--bg-elevated)', color: 'var(--text-muted)' }}>
            {raw.method === 'heuristic_audio' ? '🎵 Audio' : raw.method === 'heuristic_video' ? '🎬 Video' : raw.method}
          </span>
        )}
        {raw.detection_tier && (
          <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 8, fontWeight: 600, background: 'var(--accent-10)', color: 'var(--accent)' }}>
            {raw.detection_tier === 'primary_api' ? '⚡ Primary API'
              : raw.detection_tier === 'secondary_api' ? '🔀 Bridge API'
              : raw.detection_tier === 'local_heuristic' ? '🔬 Local Heuristic'
              : raw.detection_tier}
          </span>
        )}
      </div>

      {/* Category score bar summary */}
      {hasCategoryBreakdown && (
        <div style={{ padding: '8px 12px', background: 'var(--bg-hover)', borderBottom: hasSignals ? '1px solid var(--border)' : 'none', display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          {Object.entries(categories).map(([cat, score]) => {
            const meta = CATEGORY_META[cat] || CATEGORY_META.other
            const pct = Math.round(Math.min(score, 0.95) * 100)
            return (
              <div key={cat} style={{ display: 'flex', alignItems: 'center', gap: 5, minWidth: 0 }}>
                <div style={{ width: 6, height: 6, borderRadius: '50%', background: meta.color, flexShrink: 0 }} />
                <span style={{ fontSize: 10, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{meta.label}</span>
                <span style={{ fontSize: 10, fontWeight: 700, color: meta.color, fontFamily: 'var(--font-mono)', flexShrink: 0 }}>{pct}%</span>
              </div>
            )
          })}
        </div>
      )}

      {/* INCONCLUSIVE reason code panel — URL scan diagnostics */}
      {raw.reason_code && (
        <div style={{ padding: '10px 12px', background: 'rgba(245,158,11,0.06)', borderBottom: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
            <AlertTriangle size={13} color="var(--amber)" style={{ flexShrink: 0, marginTop: 1 }} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginBottom: 4 }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--amber)', fontFamily: 'var(--font-mono)' }}>
                  {raw.reason_code}
                </span>
                <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{raw.reason_label}</span>
              </div>
              {raw.error_detail && (
                <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', opacity: 0.7 }}>
                  {raw.error_detail.slice(0, 180)}
                </div>
              )}
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4, fontStyle: 'italic' }}>
                Authenticity cannot be verified. This reason code is recorded in the evidence bundle for audit.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Fallback tier notice */}
      {raw.fallback_used && (
        <div style={{ padding: '6px 12px', background: 'var(--bg-hover)', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 6 }}>
          <AlertTriangle size={11} color="var(--amber)" style={{ flexShrink: 0 }} />
          <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
            Primary API unavailable — results from <strong style={{ color: 'var(--text-dim)' }}>
              {raw.fallback_tier === 'secondary_api' ? 'bridge API' : 'local mathematical forensics'}
            </strong>. Accuracy may differ from primary model.
          </span>
        </div>
      )}

      {/* Per-signal breakdown grouped by category */}
      {hasSignals ? (
        <div style={{ padding: '8px 12px' }}>
          {groupOrder.map(cat => {
            const catSignals = grouped[cat]
            if (!catSignals?.length) return null
            const meta = CATEGORY_META[cat]
            return (
              <div key={cat} style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 9, fontWeight: 700, color: meta.color, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 5 }}>
                  {meta.label}
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                  {catSignals.map(([key, score]) => <SignalBar key={key} sigKey={key} score={score} />)}
                </div>
              </div>
            )
          })}

          {/* Extra photo stats */}
          {raw.classification === 'photograph' && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px 16px', marginTop: 6, paddingTop: 8, borderTop: '1px solid var(--border)' }}>
              {raw.skin_ratio !== undefined && (
                <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                  Face content: <strong style={{ color: 'var(--text-dim)' }}>{raw.has_face_content ? 'yes' : 'no'}</strong>
                  {' '}({Math.round((raw.skin_ratio || 0) * 100)}% skin-tone pixels)
                </span>
              )}
              {raw.has_camera_exif !== undefined && (
                <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                  Camera EXIF: <strong style={{ color: 'var(--text-dim)' }}>{raw.has_camera_exif ? 'present' : 'absent'}</strong>
                </span>
              )}
              {verdict && (
                <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{verdict}</span>
              )}
            </div>
          )}
        </div>
      ) : (
        <div style={{ padding: '12px', display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
            <CheckCircle size={14} color="var(--green)" style={{ flexShrink: 0, marginTop: 1 }} />
            <span style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5 }}>
              No AI synthesis signals detected. File appears to match expected natural patterns for this content type.
              {verdict && <> — <em>{verdict}</em></>}
            </span>
          </div>
          {raw.note && (
            <div style={{ fontSize: 10, color: 'var(--text-muted)', paddingLeft: 22, fontStyle: 'italic' }}>
              {raw.note}
            </div>
          )}
          {raw.c2pa_provenance && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, paddingLeft: 22 }}>
              <CheckCircle size={11} color="var(--green)" />
              <span style={{ fontSize: 10, color: 'var(--green)', fontWeight: 600 }}>
                C2PA provenance signature detected — cryptographically signed origin
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Result card ───────────────────────────────────────────────────────────────
function ScanResult({ result, file }) {
  const isSynthetic = result.is_synthetic
  const canDownload = result.evidence_bundle && Object.keys(result.evidence_bundle).length > 0

  const downloadBundle = () => {
    const blob = new Blob([JSON.stringify(result.evidence_bundle, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `kavachx-evidence-${result.scan_id?.slice(0, 8) || 'bundle'}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <Card style={{ marginTop: 24 }}>
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 20, flexWrap: 'wrap' }}>
        <div style={{ color: isSynthetic ? 'var(--red)' : 'var(--green)', opacity: 0.8, flexShrink: 0 }}>
          {fileIcon(file?.type)}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 700, fontSize: 15, color: 'var(--text)', marginBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {file?.name || 'Uploaded file'}
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
            <ActionBadge action={result.enforcement_action} />
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{formatBytes(file?.size)}</span>
          </div>
        </div>
        <ConfidenceRing value={result.confidence} synthetic={isSynthetic} />
      </div>

      {/* Detection labels */}
      {result.detection_labels?.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
            Detected Signals
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {result.detection_labels.map((label) => (
              <span key={label} style={{
                padding: '3px 9px', borderRadius: 12,
                background: 'var(--bg-hover)', color: 'var(--text-dim)',
                fontSize: 11, fontWeight: 500,
              }}>
                {label}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Detection reasoning */}
      {result.raw_response && (
        <DetectionReasoning raw={result.raw_response} />
      )}

      {/* Metadata grid */}
      <div className="scan-result-meta" style={{ marginBottom: 16 }}>
        {[
          ['Scan ID',         result.scan_id?.slice(0, 16) + '…'],
          ['BASCG Layer',     'Layer 3 — Synthetic Shield'],
          ['Content Hash',    result.content_hash?.slice(0, 24) + '…'],
          ['Election Context', result.election_context ? 'Active' : 'Inactive'],
        ].map(([k, v]) => (
          <div key={k}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 2 }}>{k}</div>
            <div style={{ fontSize: 12, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v}</div>
          </div>
        ))}
      </div>

      {/* Evidence hash */}
      {result.evidence_hash && (
        <div style={{
          padding: '10px 12px', borderRadius: 8,
          background: 'var(--bg-hover)', marginBottom: 14,
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <Hash size={12} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
          <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {result.evidence_hash}
          </span>
          <span style={{ fontSize: 9, color: 'var(--cyan)', fontWeight: 600, flexShrink: 0 }}>SHA-256</span>
        </div>
      )}

      {/* Download bundle */}
      {canDownload && (
        <button
          onClick={downloadBundle}
          style={{
            display: 'flex', alignItems: 'center', gap: 8,
            width: '100%', padding: '10px 16px', borderRadius: 8,
            background: 'var(--accent-10)', border: '1px solid var(--accent-30)',
            color: 'var(--accent)', fontSize: 13, fontWeight: 600, cursor: 'pointer',
            transition: 'background var(--t-base)',
          }}
        >
          <Download size={14} />
          Download Certificate of Analysis (IT Act S.65B)
        </button>
      )}
    </Card>
  )
}

// ── History row ───────────────────────────────────────────────────────────────
function HistoryRow({ scan }) {
  const isSynthetic = scan.is_synthetic
  return (
    <div className="history-row" style={{
      display: 'flex', alignItems: 'center', gap: 10,
      padding: '10px 0', borderBottom: '1px solid var(--border)',
    }}>
      <div style={{ color: isSynthetic ? 'var(--red)' : 'var(--green)', opacity: 0.7, flexShrink: 0 }}>
        <FileSearch size={15} />
      </div>
      <div className="history-info" style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12, color: 'var(--text)', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {scan.filename || scan.scan_id?.slice(0, 16) + '…'}
        </div>
        <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>
          {new Date(scan.created_at).toLocaleString('en-IN', { dateStyle: 'short', timeStyle: 'short' })}
        </div>
      </div>
      <div className="history-badge" style={{ flexShrink: 0 }}>
        <ActionBadge action={scan.enforcement_action} />
      </div>
      <span className="history-pct" style={{ fontSize: 11, color: 'var(--text-muted)', minWidth: 34, textAlign: 'right', fontFeatureSettings: "'tnum' 1", flexShrink: 0 }}>
        {Math.round((scan.confidence || 0) * 100)}%
      </span>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function SyntheticMediaPage() {
  const [scanning, setScanning]       = useState(false)
  const [result, setResult]           = useState(null)
  const [file, setFile]               = useState(null) // Displayed image/file
  const [urlInput, setUrlInput]       = useState('')
  const [scanMode, setScanMode]       = useState('upload') // 'upload' | 'link'
  const [error, setError]             = useState(null)
  const [history, setHistory]         = useState([])
  const [histLoading, setHistLoading] = useState(true)

  // Load scan history on mount
  useEffect(() => {
    syntheticAPI.listScans(20)
      .then(r => setHistory(Array.isArray(r.data) ? r.data : r.data?.scans || []))
      .catch(() => {})
      .finally(() => setHistLoading(false))
  }, [])

  const handleFile = async (f) => {
    setFile(f)
    setResult(null)
    setError(null)
    setScanning(true)
    setScanMode('upload')
    try {
      const res = await syntheticAPI.scan(f)
      setResult(res.data)
      setHistory(prev => [res.data, ...prev.slice(0, 19)])
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Scan failed')
    } finally {
      setScanning(false)
    }
  }

  const handleUrlScan = async (e) => {
    e?.preventDefault()
    if (!urlInput.trim()) return
    setError(null)
    setResult(null)
    setFile(null)
    setScanning(true)
    try {
      // Long timeout: yt-dlp YouTube extraction takes 15-30s + HF inference
      const res = await api.post('/synthetic-shield/scan-url', { url: urlInput }, { timeout: 120000 })
      setResult(res.data)
      setHistory(prev => [res.data, ...prev.slice(0, 19)])
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to fetch content from URL')
    } finally {
      setScanning(false)
    }
  }

  return (
    <div style={{ maxWidth: 960, margin: '0 auto' }}>
      <style>{`
        .synth-grid {
          display: grid;
          grid-template-columns: 1.4fr 1fr;
          gap: 24px;
          align-items: start;
        }
        .scan-result-meta {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 12px 16px;
        }
        @media (max-width: 900px) {
          .synth-grid {
            grid-template-columns: 1fr;
          }
        }
        @media (max-width: 500px) {
          .scan-result-meta {
            grid-template-columns: 1fr;
          }
          .history-row {
            flex-wrap: wrap;
            gap: 8px;
          }
          .history-info {
            order: 1;
            width: calc(100% - 100px);
          }
          .history-badge {
            order: 2;
          }
          .history-pct {
            order: 3;
            width: 100%;
            text-align: left !important;
            padding-left: 25px;
          }
        }
        @keyframes spin {
          from { transform: rotate(0deg); }
          to   { transform: rotate(360deg); }
        }
      `}</style>

      <div className="page-header">
        <div className="page-eyebrow">BASCG Layer 3</div>
        <h1 className="page-title">Synthetic Media Verifier</h1>
        <p className="page-desc">
          Upload an image, video, or audio file to detect AI-generated or deepfake content.
          Generates a tamper-evident Certificate of Analysis under IT Act S.65B.
        </p>
      </div>

      <div className="synth-grid">
        {/* Left: upload + result */}
        <div>
          {/* Scan Tabs */}
          <div style={{ display: 'flex', gap: 4, background: 'var(--bg-card)', padding: 4, borderRadius: 10, marginBottom: 16, border: '1px solid var(--border)' }}>
            <button
              onClick={() => setScanMode('upload')}
              style={{
                flex: 1, padding: '8px 12px', borderRadius: 6, fontSize: 13, fontWeight: 600, border: 'none', cursor: 'pointer',
                background: scanMode === 'upload' ? 'var(--accent)' : 'transparent',
                color: scanMode === 'upload' ? 'white' : 'var(--text-muted)',
                transition: 'all var(--t-base)'
              }}
            >
              Upload File
            </button>
            <button
              onClick={() => setScanMode('link')}
              style={{
                flex: 1, padding: '8px 12px', borderRadius: 6, fontSize: 13, fontWeight: 600, border: 'none', cursor: 'pointer',
                background: scanMode === 'link' ? 'var(--accent)' : 'transparent',
                color: scanMode === 'link' ? 'white' : 'var(--text-muted)',
                transition: 'all var(--t-base)'
              }}
            >
              Scan Link
            </button>
          </div>

          {scanMode === 'upload' ? (
            <DropZone onFile={handleFile} scanning={scanning} />
          ) : (
            <Card style={{ padding: 20 }}>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Social Media / Web Link</div>
              <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16 }}>Paste a YouTube Reel, Instagram post, or any image URL to verify its authenticity.</p>
              <form onSubmit={handleUrlScan} style={{ display: 'flex', gap: 8 }}>
                <input
                  type="text"
                  placeholder="https://www.youtube.com/reels/..."
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  style={{
                    flex: 1, padding: '10px 14px', borderRadius: 8, border: '1px solid var(--border)',
                    background: 'var(--bg-hover)', color: 'var(--text)', fontSize: 13, outline: 'none'
                  }}
                  disabled={scanning}
                />
                <button
                  type="submit"
                  disabled={scanning || !urlInput.trim()}
                  style={{
                    padding: '0 20px', borderRadius: 8, background: 'var(--accent)', color: 'white',
                    border: 'none', fontSize: 13, fontWeight: 700, cursor: 'pointer', opacity: (scanning || !urlInput.trim()) ? 0.6 : 1
                  }}
                >
                  {scanning ? '...' : 'Verify'}
                </button>
              </form>
            </Card>
          )}

          {error && (
            <div style={{
              marginTop: 16, padding: '12px 16px', borderRadius: 8,
              background: 'var(--red-10)', border: '1px solid var(--red-30)',
              color: 'var(--red)', fontSize: 13,
            }}>
              {error}
            </div>
          )}

          {result && <ScanResult result={result} file={file} />}
        </div>

        {/* Right: scan history + info */}
        <div>
          <Card>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)' }}>Recent Scans</div>
              <div style={{
                padding: '2px 8px', borderRadius: 10,
                background: 'var(--accent-10)', color: 'var(--accent)',
                fontSize: 10, fontWeight: 700,
              }}>
                {history.length}
              </div>
            </div>

            {histLoading ? (
              <div style={{ color: 'var(--text-muted)', fontSize: 12, textAlign: 'center', padding: '20px 0' }}>Loading…</div>
            ) : history.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: 12, textAlign: 'center', padding: '20px 0' }}>
                No scans yet — upload a file to start
              </div>
            ) : (
              history.map((s, i) => <HistoryRow key={s.scan_id || i} scan={s} />)
            )}
          </Card>

          {/* Info card */}
          <Card style={{ marginTop: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text)', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
              <ShieldCheck size={13} color="var(--accent)" /> How it works
            </div>
            {[
              ['Detection', 'Hash-fingerprint + signal analysis for GAN, diffusion, and splice artifacts.'],
              ['Evidence Bundle', 'Ed25519-signed JSON with timestamps — admissible under IT Act S.65B.'],
              ['Election Mode', 'Political deepfakes auto-escalate to ECI integrity bus when enabled.'],
            ].map(([title, desc]) => (
              <div key={title} style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-dim)' }}>{title}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.6 }}>{desc}</div>
              </div>
            ))}
          </Card>
        </div>
      </div>
    </div>
  )
}
