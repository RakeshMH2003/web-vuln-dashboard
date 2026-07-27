import React from 'react';

const SEVERITY_COLORS = {
  Critical: { bg: 'rgba(239,68,68,0.15)', color: '#f87171', border: '#ef4444' },
  High:     { bg: 'rgba(249,115,22,0.15)', color: '#fb923c', border: '#f97316' },
  Medium:   { bg: 'rgba(234,179,8,0.15)',  color: '#facc15', border: '#eab308' },
  Low:      { bg: 'rgba(34,197,94,0.15)',  color: '#4ade80', border: '#22c55e' },
};

export function SeverityBadge({ severity }) {
  const c = SEVERITY_COLORS[severity] || SEVERITY_COLORS.Low;
  return (
    <span style={{
      background: c.bg, color: c.color, border: `1px solid ${c.border}`,
      padding: '3px 10px', borderRadius: '20px', fontSize: '12px', fontWeight: 600,
      whiteSpace: 'nowrap',
    }}>
      {severity}
    </span>
  );
}

export function StatCard({ label, value, color = '#38bdf8', sub }) {
  return (
    <div style={{
      background: '#1e293b', border: '1px solid #334155', borderRadius: '12px',
      padding: '20px 24px', flex: 1, minWidth: '140px',
    }}>
      <p style={{ color: '#64748b', fontSize: '12px', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</p>
      <p style={{ color, fontSize: '32px', fontWeight: 700, lineHeight: 1 }}>{value}</p>
      {sub && <p style={{ color: '#64748b', fontSize: '12px', marginTop: '6px' }}>{sub}</p>}
    </div>
  );
}

export function FindingCard({ finding }) {
  const [open, setOpen] = React.useState(false);
  const c = SEVERITY_COLORS[finding.severity] || SEVERITY_COLORS.Low;

  return (
    <div style={{
      background: '#1e293b', border: `1px solid #334155`,
      borderLeft: `3px solid ${c.border}`,
      borderRadius: '8px', marginBottom: '10px', overflow: 'hidden',
    }}>
      <div
        onClick={() => setOpen(!open)}
        style={{
          display: 'flex', alignItems: 'center', gap: '12px',
          padding: '14px 16px', cursor: 'pointer',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <SeverityBadge severity={finding.severity} />
          <span style={{ color: '#e2e8f0', fontSize: '14px', fontWeight: 500 }}>
            {finding.vuln_type}
          </span>
        </div>
        <span style={{ color: '#64748b', fontSize: '18px', transition: 'transform 0.2s', display: 'inline-block', transform: open ? 'rotate(180deg)' : 'rotate(0deg)' }}>▾</span>
      </div>

      {open && (
        <div style={{ padding: '0 16px 16px', borderTop: '1px solid #334155' }}>
          <div style={{ marginTop: '14px' }}>
            <p style={{ color: '#94a3b8', fontSize: '12px', fontWeight: 600, marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Description</p>
            <p style={{ color: '#cbd5e1', fontSize: '14px', lineHeight: '1.6' }}>{finding.description}</p>
          </div>
          <div style={{ marginTop: '14px', background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)', borderRadius: '8px', padding: '12px 14px' }}>
            <p style={{ color: '#4ade80', fontSize: '12px', fontWeight: 600, marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>How to Fix</p>
            <p style={{ color: '#cbd5e1', fontSize: '14px', lineHeight: '1.6' }}>{finding.fix}</p>
          </div>
        </div>
      )}
    </div>
  );
}

export function RiskScore({ score }) {
  const color = score >= 70 ? '#f87171' : score >= 40 ? '#fb923c' : score >= 20 ? '#facc15' : '#4ade80';
  const label = score >= 70 ? 'Critical Risk' : score >= 40 ? 'High Risk' : score >= 20 ? 'Medium Risk' : 'Low Risk';
  const pct = Math.min(score, 100);

  return (
    <div style={{ textAlign: 'center' }}>
      <div style={{ position: 'relative', display: 'inline-block' }}>
        <svg width="120" height="120" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="50" fill="none" stroke="#334155" strokeWidth="10"/>
          <circle cx="60" cy="60" r="50" fill="none" stroke={color} strokeWidth="10"
            strokeDasharray={`${pct * 3.14} 314`}
            strokeLinecap="round"
            transform="rotate(-90 60 60)"
          />
        </svg>
        <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', textAlign: 'center' }}>
          <div style={{ color, fontSize: '26px', fontWeight: 700 }}>{score}</div>
          <div style={{ color: '#64748b', fontSize: '10px' }}>/100</div>
        </div>
      </div>
      <p style={{ color, fontSize: '13px', fontWeight: 600, marginTop: '6px' }}>{label}</p>
    </div>
  );
}
