import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

export default function HistoryPage() {
  const [scans, setScans] = useState([]);
  const navigate = useNavigate();

  const fetchScans = () => axios.get('/api/scans').then(r => setScans(r.data)).catch(() => {});
  useEffect(() => { fetchScans(); }, []);

  const deleteScan = async (id) => {
    if (!window.confirm('Delete this scan?')) return;
    await axios.delete(`/api/scans/${id}`);
    fetchScans();
  };

  const riskColor = (score) => score >= 70 ? '#f87171' : score >= 40 ? '#fb923c' : score >= 20 ? '#facc15' : '#4ade80';
  const riskLabel = (score) => score >= 70 ? 'Critical' : score >= 40 ? 'High' : score >= 20 ? 'Medium' : 'Low';

  return (
    <div>
      <div style={{ marginBottom: '28px' }}>
        <h1 style={{ color: '#f1f5f9', fontSize: '24px', fontWeight: 700, marginBottom: '6px' }}>Scan History</h1>
        <p style={{ color: '#64748b', fontSize: '14px' }}>All previous vulnerability scans</p>
      </div>

      <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '12px', overflow: 'hidden' }}>
        {scans.length === 0 ? (
          <div style={{ padding: '60px', textAlign: 'center' }}>
            <p style={{ color: '#475569', fontSize: '16px', marginBottom: '16px' }}>No scans yet</p>
            <button onClick={() => navigate('/scan')} style={{
              background: '#38bdf8', color: '#0f172a', border: 'none',
              borderRadius: '8px', padding: '10px 24px', fontSize: '14px', fontWeight: 600, cursor: 'pointer'
            }}>Run First Scan</button>
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead style={{ background: '#0f172a' }}>
              <tr>
                {['#', 'URL', 'Scanned At', 'Findings', 'Risk Level', 'Score', 'Actions'].map(h => (
                  <th key={h} style={{
                    textAlign: 'left', color: '#64748b', fontSize: '11px', fontWeight: 600,
                    padding: '12px 16px', textTransform: 'uppercase', letterSpacing: '0.05em',
                    borderBottom: '1px solid #334155'
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {scans.map((scan, idx) => (
                <tr key={scan.id} style={{ borderBottom: '1px solid #1e293b' }}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <td style={{ padding: '14px 16px', color: '#475569', fontSize: '13px' }}>{idx + 1}</td>
                  <td style={{ padding: '14px 16px', maxWidth: '280px' }}>
                    <p style={{ color: '#e2e8f0', fontSize: '14px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{scan.url}</p>
                  </td>
                  <td style={{ padding: '14px 16px', color: '#64748b', fontSize: '13px', whiteSpace: 'nowrap' }}>{scan.scanned_at}</td>
                  <td style={{ padding: '14px 16px', color: '#a78bfa', fontSize: '14px', fontWeight: 600 }}>{scan.total_findings}</td>
                  <td style={{ padding: '14px 16px' }}>
                    <span style={{
                      background: `${riskColor(scan.risk_score)}20`,
                      color: riskColor(scan.risk_score),
                      border: `1px solid ${riskColor(scan.risk_score)}40`,
                      padding: '3px 10px', borderRadius: '20px', fontSize: '12px', fontWeight: 600
                    }}>{riskLabel(scan.risk_score)}</span>
                  </td>
                  <td style={{ padding: '14px 16px', color: riskColor(scan.risk_score), fontSize: '16px', fontWeight: 700 }}>{scan.risk_score}</td>
                  <td style={{ padding: '14px 16px' }}>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button onClick={() => navigate(`/results/${scan.id}`)} style={{
                        background: 'transparent', border: '1px solid #334155', color: '#94a3b8',
                        borderRadius: '6px', padding: '5px 12px', fontSize: '12px', cursor: 'pointer'
                      }}>View</button>
                      <button onClick={() => deleteScan(scan.id)} style={{
                        background: 'transparent', border: '1px solid rgba(239,68,68,0.3)', color: '#f87171',
                        borderRadius: '6px', padding: '5px 12px', fontSize: '12px', cursor: 'pointer'
                      }}>Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
