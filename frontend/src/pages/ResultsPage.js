import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { SeverityBadge, FindingCard, RiskScore } from '../components/Components';

const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };
const SEV_COLORS = { Critical: '#f87171', High: '#fb923c', Medium: '#facc15', Low: '#4ade80' };

function OpenPortsPanel({ findings }) {
  const portFindings = findings.filter(f => f.vuln_type.startsWith('Open Port:'));
  if (portFindings.length === 0) return null;

  return (
    <div style={{ background: '#1e293b', border: '1px solid #ef444440', borderRadius: '12px', padding: '20px', marginBottom: '20px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
        <div style={{ background: 'rgba(239,68,68,0.15)', border: '1px solid #ef444460', borderRadius: '8px', padding: '6px 10px' }}>
          <span style={{ fontSize: '16px' }}>🔌</span>
        </div>
        <div>
          <h2 style={{ color: '#f87171', fontSize: '15px', fontWeight: 700, margin: 0 }}>Open Dangerous Ports Detected</h2>
          <p style={{ color: '#64748b', fontSize: '12px', margin: 0 }}>{portFindings.length} dangerous port{portFindings.length > 1 ? 's' : ''} exposed to the internet</p>
        </div>
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px' }}>
        {portFindings.map((f, i) => {
          const portMatch = f.vuln_type.match(/(\d+)\/(\w+)/);
          const port = portMatch ? portMatch[1] : '?';
          const service = portMatch ? portMatch[2] : '?';
          const color = SEV_COLORS[f.severity] || '#4ade80';
          return (
            <div key={i} style={{
              background: `${color}15`,
              border: `1px solid ${color}40`,
              borderRadius: '10px',
              padding: '12px 16px',
              minWidth: '120px',
              textAlign: 'center',
            }}>
              <div style={{ color: color, fontSize: '22px', fontWeight: 800 }}>{port}</div>
              <div style={{ color: '#e2e8f0', fontSize: '12px', fontWeight: 600 }}>{service}</div>
              <div style={{
                marginTop: '6px',
                background: `${color}25`,
                color: color,
                borderRadius: '20px',
                padding: '2px 8px',
                fontSize: '10px',
                fontWeight: 700,
              }}>{f.severity}</div>
            </div>
          );
        })}
      </div>

      <div style={{ marginTop: '14px', background: 'rgba(239,68,68,0.07)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: '8px', padding: '10px 14px' }}>
        <p style={{ color: '#94a3b8', fontSize: '12px', margin: 0 }}>
          ⚠️ These ports are accessible from the public internet. Restrict them using a firewall (e.g., Windows Firewall, iptables, AWS Security Groups) to trusted IP addresses only.
        </p>
      </div>
    </div>
  );
}

export default function ResultsPage() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [filter, setFilter] = useState('All');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios.get(`/api/scans/${scanId}`)
      .then(r => { setData(r.data); setLoading(false); })
      .catch(() => { setLoading(false); });
  }, [scanId]);

  if (loading) return <p style={{ color: '#64748b', padding: '40px 0' }}>Loading results...</p>;
  if (!data) return <p style={{ color: '#f87171', padding: '40px 0' }}>Scan not found.</p>;

  const { scan, findings } = data;
  const sorted = [...findings].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  const filtered = filter === 'All' ? sorted : sorted.filter(f => f.severity === filter);
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px' }}>
        <button onClick={() => navigate(-1)} style={{
          background: 'transparent', border: '1px solid #334155', color: '#94a3b8',
          borderRadius: '8px', padding: '7px 14px', fontSize: '13px', cursor: 'pointer'
        }}>← Back</button>
        <div>
          <h1 style={{ color: '#f1f5f9', fontSize: '20px', fontWeight: 700 }}>Scan Results</h1>
          <p style={{ color: '#64748b', fontSize: '13px' }}>{scan.url} · {scan.scanned_at}</p>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '20px', marginBottom: '28px', flexWrap: 'wrap', alignItems: 'stretch' }}>
        <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '12px', padding: '24px 28px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minWidth: '160px' }}>
          <RiskScore score={scan.risk_score} />
        </div>

        <div style={{ flex: 1, display: 'grid', gridTemplateColumns: 'repeat(2,1fr)', gap: '12px' }}>
          {Object.entries(counts).map(([sev, count]) => (
            <div key={sev} style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '10px', padding: '14px 18px' }}>
              <p style={{ color: '#64748b', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px' }}>{sev}</p>
              <p style={{ color: SEV_COLORS[sev], fontSize: '28px', fontWeight: 700 }}>{count}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Dedicated Open Ports Panel */}
      <OpenPortsPanel findings={findings} />

      <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '12px', padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
          <h2 style={{ color: '#f1f5f9', fontSize: '15px', fontWeight: 600 }}>
            All Findings ({filtered.length})
          </h2>
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {['All', 'Critical', 'High', 'Medium', 'Low'].map(s => (
              <button key={s} onClick={() => setFilter(s)} style={{
                background: filter === s ? 'rgba(56,189,248,0.15)' : 'transparent',
                border: `1px solid ${filter === s ? '#38bdf8' : '#334155'}`,
                color: filter === s ? '#38bdf8' : '#64748b',
                borderRadius: '6px', padding: '5px 12px', fontSize: '12px', cursor: 'pointer', fontWeight: 500,
              }}>{s}</button>
            ))}
          </div>
        </div>

        {filtered.length === 0 ? (
          <div style={{ padding: '40px 0', textAlign: 'center' }}>
            <p style={{ color: '#4ade80', fontSize: '18px', fontWeight: 700, marginBottom: '6px' }}>No findings for this filter</p>
            <p style={{ color: '#64748b', fontSize: '14px' }}>
              {findings.length === 0 ? 'No vulnerabilities were detected. The site looks secure!' : 'Try a different severity filter.'}
            </p>
          </div>
        ) : (
          filtered.map((f, i) => <FindingCard key={i} finding={f} />)
        )}
      </div>

      <div style={{ marginTop: '16px', display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
        <button onClick={() => navigate('/scan')} style={{
          background: '#38bdf8', color: '#0f172a', border: 'none',
          borderRadius: '8px', padding: '10px 20px', fontSize: '14px', fontWeight: 600, cursor: 'pointer'
        }}>Scan Another URL</button>
      </div>
    </div>
  );
}

