import { useState } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import { USE_MOCK } from '../api/client';
import { Button, Field, Notice } from '../components/ui';

export default function Login() {
  const { user, login } = useAuth();
  const loc = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [hint, setHint] = useState(false);

  if (user) return <Navigate to={loc.state?.from ?? (user.isAdmin ? '/admin/accounts' : '/dashboard')} replace />;

  async function resetDemo() {
    const { resetMock } = await import('../api/mock.js');
    await resetMock();
    location.reload();
  }

  async function submit(e) {
    e.preventDefault(); setBusy(true); setErr('');
    try { await login(email.trim(), password); }
    catch (x) { setErr(x.status === 401 || x.status === 403 ? 'Email or password is incorrect, or the account is inactive.' : x.message); setBusy(false); }
  }
  return (
    <div className="login">
      <div className="login-inner">
        <section className="login-hero">
          <b className="brand-name">HOSPITAL WORKSPACE</b>
          <small>Hospital information system</small>
          <h1>Your hospital.<br />Everything in one place.</h1>
          <p>Access hospital applications, tools and shared workspaces.</p>
        </section>
        <form className="login-card" onSubmit={submit}>
          <h2>Welcome back</h2>
          <p className="sub">Sign in with your hospital account.</p>
          {err && <Notice tone="danger">{err}</Notice>}
          <Field label="Hospital email" htmlFor="email"><input id="email" className="input" type="email" required autoFocus autoComplete="username" placeholder="name@hospital.org" value={email} onChange={(e) => setEmail(e.target.value)} /></Field>
          <Field label="Password" htmlFor="pw"><input id="pw" className="input" type="password" required autoComplete="current-password" placeholder="Enter your password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
          <p style={{ margin: '4px 0 22px' }}><button type="button" className="linkbtn" style={{ fontSize: 13 }} onClick={() => setHint(true)}>Forgot password?</button></p>
          {hint && <Notice>Password resets are handled by your hospital administrator.</Notice>}
          <Button variant="primary" block type="submit" disabled={busy || !email || !password}>{busy ? 'Signing in…' : 'Sign in'}</Button>
          <p className="small">Need access? Contact your hospital administrator.</p>
          {USE_MOCK && <p className="small">Demo data (mock): riley@ · alex@ · sam@ · admin@hospital.org, any password. <button type="button" className="linkbtn" onClick={resetDemo}>Reset demo data</button></p>}
        </form>
      </div>
      <p className="login-foot">MedShare is available inside the hospital workspace for authorized staff.</p>
    </div>
  );
}
