import React, { useEffect, useState } from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';
import axios from 'axios';
import { StatCard } from '../components/Components';
import { useNavigate } from 'react-router-dom';

const COLORS = { Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#22c55e' };

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [scans, setScans] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    axios.get('/api/stats').then(r => setStats(r.data)).catch(() => {});
    axios.get('/api/scans').then(r => setScans(r.data)).catch(() => {});
  }, []);

  const pieData = stats ? Object.entries(stats.by_severity).map(([name, value]) => ({ name, value })).filter(d => d.value > 0) : [];

  return (
    <div>
      <div style={{ marginBottom: '28px' }}>
        <h1 style={{ color: '#f1f5f9', fontSize: '24px', fontWeight: 700, marginBottom: '6px' }}>Dashboard</h1>
        <p style={{ color: '#64748b', fontSize: '14px' }}>Overview of all scans and vulnerabilities detected</p>
      </div>

      {stats && (
        <div style={{ display: 'flex', gap: '16px', marginBottom: '28px', flexWrap: 'wrap' }}>
          <StatCard label="Total Scans" value={stats.total_scans} color="#38bdf8" />
          <StatCard label="Total Findings" value={stats.total_findings} color="#a78bfa" />
          <StatCard label="Critical" value={stats.by_severity.Critical} color="#f87171" />
          <StatCard label="High" value={stats.by_severity.High} color="#fb923c" />
          <StatCard label="Medium" value={stats.by_severity.Medium} color="#facc15" />
          <StatCard label="Low" value={stats.by_severity.Low} color="#4ade80" />
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '28px' }}>
        <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '12px', padding: '20px' }}>
          <h2 style={{ color: '#f1f5f9', fontSize: '15px', fontWeight: 600, marginBottom: '20px' }}>Findings by Severity</h2>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" outerRadius={80} dataKey="value" label={({ name, value }) => `${name}: ${value}`} labelLine={false}>
                  {pieData.map((entry) => <Cell key={entry.name} fill={COLORS[entry.name]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155', color: '#e2e8f0', borderRadius: '8px' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ height: '220px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#475569' }}>
              No data yet — run your first scan
            </div>
          )}
        </div>

        <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '12px', padding: '20px' }}>
          <h2 style={{ color: '#f1f5f9', fontSize: '15px', fontWeight: 600, marginBottom: '20px' }}>Recent Scan Risk Scores</h2>
          {scans.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={scans.slice(0, 8).reverse().map(s => ({ name: new URL(s.url).hostname.substring(0, 15), score: s.risk_score }))}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 11 }} />
                <YAxis tick={{ fill: '#64748b', fontSize: 11 }} domain={[0, 100]} />
                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155', color: '#e2e8f0', borderRadius: '8px' }} />
                <Bar dataKey="score" fill="#38bdf8" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ height: '220px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#475569' }}>
              No scans yet
            </div>
          )}
        </div>
      </div>

      <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '12px', padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h2 style={{ color: '#f1f5f9', fontSize: '15px', fontWeight: 600 }}>Recent Scans</h2>
          <button onClick={() => navigate('/scan')} style={{
            background: '#38bdf8', color: '#0f172a', border: 'none', borderRadius: '8px',
            padding: '8px 16px', fontSize: '13px', fontWeight: 600, cursor: 'pointer'
          }}>+ New Scan</button>
        </div>

        {scans.length === 0 ? (
          <p style={{ color: '#475569', fontSize: '14px', padding: '20px 0' }}>No scans yet. Start by scanning a URL.</p>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                {['URL', 'Date', 'Findings', 'Risk Score', ''].map(h => (
                  <th key={h} style={{ textAlign: 'left', color: '#64748b', fontSize: '12px', fontWeight: 600, padding: '8px 12px', textTransform: 'uppercase', letterSpacing: '0.05em', borderBottom: '1px solid #334155' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {scans.map(scan => (
                <tr key={scan.id} style={{ borderBottom: '1px solid #1e293b' }}>
                  <td style={{ padding: '12px', color: '#e2e8f0', fontSize: '14px', maxWidth: '260px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{scan.url}</td>
                  <td style={{ padding: '12px', color: '#64748b', fontSize: '13px', whiteSpace: 'nowrap' }}>{scan.scanned_at}</td>
                  <td style={{ padding: '12px', color: '#a78bfa', fontSize: '14px', fontWeight: 600 }}>{scan.total_findings}</td>
                  <td style={{ padding: '12px' }}>
                    <span style={{ color: scan.risk_score >= 70 ? '#f87171' : scan.risk_score >= 40 ? '#fb923c' : scan.risk_score >= 20 ? '#facc15' : '#4ade80', fontWeight: 700 }}>
                      {scan.risk_score}
                    </span>
                    <span style={{ color: '#475569', fontSize: '12px' }}>/100</span>
                  </td>
                  <td style={{ padding: '12px' }}>
                    <button onClick={() => navigate(`/results/${scan.id}`)} style={{
                      background: 'transparent', border: '1px solid #334155', color: '#94a3b8',
                      borderRadius: '6px', padding: '5px 12px', fontSize: '12px', cursor: 'pointer'
                    }}>View</button>
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
