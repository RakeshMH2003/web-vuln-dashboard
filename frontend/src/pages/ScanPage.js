import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const EXAMPLE_TARGETS = [
  'http://testphp.vulnweb.com',
  'http://demo.testfire.net',
  'http://zero.webappsecurity.com',
];

export default function ScanPage() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [step, setStep] = useState('');
  const navigate = useNavigate();

  const steps = [
    'Connecting to target...',
    'Checking SSL certificate...',
    'Scanning HTTP security headers...',
    'Probing for XSS vulnerabilities...',
    'Testing for SQL injection...',
    'Checking sensitive exposed paths...',
    'Inspecting cookies...',
    'Checking for information disclosure...',
    'Verifying Subresource Integrity (SRI)...',
    'Testing for directory listing...',
    'Analyzing CORS configuration...',
    'Scanning for open dangerous ports...',
    'Reading robots.txt for hidden paths...',
    'Checking for hidden form field tampering...',
    'Calculating risk score...',
  ];

  const handleScan = async () => {
    if (!url.trim()) { setError('Please enter a URL'); return; }
    setError('');
    setLoading(true);

    let i = 0;
    setStep(steps[0]);
    const interval = setInterval(() => {
      i = (i + 1) % steps.length;
      setStep(steps[i]);
    }, 1400);

    try {
      const res = await axios.post('/api/scan', { url });
      clearInterval(interval);
      navigate(`/results/${res.data.scan_id}`);
    } catch (e) {
      clearInterval(interval);
      setError(e.response?.data?.error || 'Scan failed. Make sure the URL is reachable and the backend is running.');
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: '680px', margin: '0 auto' }}>
      <div style={{ marginBottom: '32px' }}>
        <h1 style={{ color: '#f1f5f9', fontSize: '24px', fontWeight: 700, marginBottom: '6px' }}>New Vulnerability Scan</h1>
        <p style={{ color: '#64748b', fontSize: '14px' }}>Enter a URL to scan for common web vulnerabilities</p>
      </div>

      <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '16px', padding: '32px' }}>
        <label style={{ color: '#94a3b8', fontSize: '13px', fontWeight: 600, display: 'block', marginBottom: '10px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Target URL
        </label>

        <div style={{ display: 'flex', gap: '12px', marginBottom: '12px' }}>
          <input
            type="text"
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && !loading && handleScan()}
            placeholder="https://example.com"
            disabled={loading}
            style={{
              flex: 1, background: '#0f172a', border: '1px solid #334155',
              borderRadius: '8px', padding: '12px 16px', color: '#e2e8f0',
              fontSize: '15px', outline: 'none',
              opacity: loading ? 0.6 : 1,
            }}
          />
          <button
            onClick={handleScan}
            disabled={loading}
            style={{
              background: loading ? '#334155' : '#38bdf8',
              color: loading ? '#64748b' : '#0f172a',
              border: 'none', borderRadius: '8px',
              padding: '12px 24px', fontSize: '14px', fontWeight: 700,
              cursor: loading ? 'not-allowed' : 'pointer',
              whiteSpace: 'nowrap', minWidth: '120px',
            }}
          >
            {loading ? 'Scanning...' : 'Scan Now'}
          </button>
        </div>

        {error && (
          <div style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '8px', padding: '12px 16px', color: '#f87171', fontSize: '14px', marginBottom: '12px' }}>
            {error}
          </div>
        )}

        {loading && (
          <div style={{ marginTop: '24px', textAlign: 'center' }}>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '6px', marginBottom: '16px' }}>
              {[0, 1, 2].map(i => (
                <div key={i} style={{
                  width: '8px', height: '8px', borderRadius: '50%', background: '#38bdf8',
                  animation: `bounce 1.2s ease-in-out ${i * 0.2}s infinite`,
                }} />
              ))}
            </div>
            <p style={{ color: '#38bdf8', fontSize: '14px', fontWeight: 500 }}>{step}</p>
            <style>{`@keyframes bounce { 0%,80%,100%{transform:scale(0.8);opacity:0.5} 40%{transform:scale(1.2);opacity:1} }`}</style>
          </div>
        )}

        <div style={{ marginTop: '24px', borderTop: '1px solid #334155', paddingTop: '20px' }}>
          <p style={{ color: '#64748b', fontSize: '12px', marginBottom: '10px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Try these vulnerable test sites (safe to scan)
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
            {EXAMPLE_TARGETS.map(t => (
              <button key={t} onClick={() => setUrl(t)} disabled={loading} style={{
                background: 'transparent', border: '1px solid #334155', color: '#94a3b8',
                borderRadius: '6px', padding: '6px 12px', fontSize: '12px', cursor: 'pointer',
              }}>{t}</button>
            ))}
          </div>
        </div>
      </div>

      <div style={{ marginTop: '24px', background: '#1e293b', border: '1px solid #334155', borderRadius: '12px', padding: '20px' }}>
        <h3 style={{ color: '#f1f5f9', fontSize: '14px', fontWeight: 600, marginBottom: '14px' }}>What this scanner checks</h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
          {[
            ['SSL/TLS Certificate', 'HTTPS enforcement, cert expiry'],
            ['Security Headers', 'CSP, HSTS, X-Frame-Options...'],
            ['XSS Detection', 'Reflected input in forms'],
            ['SQL Injection', 'Error-based detection'],
            ['Sensitive Paths', '/admin, /.env, /.git...'],
            ['Cookie Security', 'Secure, HttpOnly, SameSite flags'],
            ['Info Disclosure', 'Leaked server versions'],
            ['Missing SRI', 'Insecure third-party scripts'],
            ['Directory Listing', 'Exposed public folders'],
            ['CORS Config', 'Overly permissive origin rules'],
            ['Open Ports', 'FTP, SSH, MySQL, RDP, Redis...'],
            ['robots.txt Paths', 'Hidden admin & staging paths'],
            ['Hidden Form Fields', 'Tamperable price/role fields'],
          ].map(([title, desc]) => (
            <div key={title} style={{ display: 'flex', gap: '10px', alignItems: 'flex-start' }}>
              <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#38bdf8', marginTop: '5px', flexShrink: 0 }} />
              <div>
                <p style={{ color: '#e2e8f0', fontSize: '13px', fontWeight: 500 }}>{title}</p>
                <p style={{ color: '#64748b', fontSize: '12px' }}>{desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
