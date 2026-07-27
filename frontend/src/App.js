import React from 'react';
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import ScanPage from './pages/ScanPage';
import ResultsPage from './pages/ResultsPage';
import HistoryPage from './pages/HistoryPage';

const styles = {
  app: { minHeight: '100vh', background: '#0f172a' },
  nav: {
    background: '#1e293b',
    borderBottom: '1px solid #334155',
    padding: '0 24px',
    display: 'flex',
    alignItems: 'center',
    gap: '32px',
    height: '56px',
  },
  brand: { color: '#38bdf8', fontWeight: 700, fontSize: '16px', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '8px' },
  navLinks: { display: 'flex', gap: '4px', marginLeft: '16px' },
  link: {
    color: '#94a3b8', textDecoration: 'none', padding: '6px 14px',
    borderRadius: '6px', fontSize: '14px', fontWeight: 500,
    transition: 'all 0.15s',
  },
  activeLink: {
    color: '#38bdf8', background: 'rgba(56,189,248,0.1)',
  },
  content: { padding: '32px 24px', maxWidth: '1100px', margin: '0 auto' },
};

export default function App() {
  return (
    <BrowserRouter>
      <div style={styles.app}>
        <nav style={styles.nav}>
          <NavLink to="/" style={styles.brand}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            VulnDash
          </NavLink>
          <div style={styles.navLinks}>
            {[['/', 'Dashboard'], ['/scan', 'New Scan'], ['/history', 'History']].map(([to, label]) => (
              <NavLink key={to} to={to} end={to === '/'} style={({ isActive }) => ({
                ...styles.link, ...(isActive ? styles.activeLink : {})
              })}>
                {label}
              </NavLink>
            ))}
          </div>
        </nav>
        <div style={styles.content}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scan" element={<ScanPage />} />
            <Route path="/results/:scanId" element={<ResultsPage />} />
            <Route path="/history" element={<HistoryPage />} />
          </Routes>
        </div>
      </div>
    </BrowserRouter>
  );
}
