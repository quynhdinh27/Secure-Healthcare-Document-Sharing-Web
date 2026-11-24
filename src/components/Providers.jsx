import { createContext, useCallback, useContext, useState } from 'react';
import { api } from '../api/endpoints';
import { Button, Field, Modal } from './ui';

/* ---- Toast ---- */
const ToastCtx = createContext(() => {});
export const useToast = () => useContext(ToastCtx);
export function ToastProvider({ children }) {
  const [list, setList] = useState([]);
  const toast = useCallback((message, tone) => {
    const id = Math.random();
    setList((l) => [...l, { id, message, tone }]);
    setTimeout(() => setList((l) => l.filter((t) => t.id !== id)), 5000);
  }, []);
  return (
    <ToastCtx.Provider value={toast}>
      {children}
      <div className="toasts" aria-live="polite">{list.map((t) => <div key={t.id} className={`toast ${t.tone || ''}`}>{t.message}</div>)}</div>
    </ToastCtx.Provider>
  );
}

/* ---- Reauthenticate: await reauth() → true nếu xác thực lại thành công ---- */
const ReauthCtx = createContext(async () => true);
export const useReauth = () => useContext(ReauthCtx);
export function ReauthProvider({ children }) {
  const [req, setReq] = useState(null);
  const [pw, setPw] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const ask = useCallback(() => new Promise((resolve) => { setPw(''); setErr(''); setReq({ resolve }); }), []);
  const close = (ok) => { req.resolve(ok); setReq(null); };
  async function submit(e) {
    e.preventDefault(); setBusy(true); setErr('');
    try { await api.reauthenticate(pw); close(true); } catch (x) { setErr(x.message); } finally { setBusy(false); }
  }
  return (
    <ReauthCtx.Provider value={ask}>
      {children}
      {req && (
        <Modal title="Confirm it’s you" lead="Enter your password to continue with this sensitive action." onClose={() => close(false)}>
          <form onSubmit={submit}>
            <Field label="Password" htmlFor="reauth-pw">
              <input id="reauth-pw" className="input" type="password" autoFocus value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" />
            </Field>
            {err && <p style={{ color: 'var(--danger)', fontSize: 12, marginBottom: 12 }}>{err}</p>}
            <div className="form-actions" style={{ marginTop: 8 }}>
              <Button onClick={() => close(false)}>Cancel</Button>
              <Button variant="primary" type="submit" disabled={!pw || busy}>{busy ? 'Checking…' : 'Confirm'}</Button>
            </div>
          </form>
        </Modal>
      )}
    </ReauthCtx.Provider>
  );
}
