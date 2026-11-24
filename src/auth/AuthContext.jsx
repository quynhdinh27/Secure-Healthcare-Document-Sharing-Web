import { createContext, useContext, useEffect, useState } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { api } from '../api/endpoints';
import { setUnauthorizedHandler } from '../api/client';
import { nUser } from '../api/normalize';
import { Loading } from '../components/ui';

const Ctx = createContext(null);
export const useAuth = () => useContext(Ctx);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    setUnauthorizedHandler(() => setUser(null));
    api.getCurrentUser().then((r) => setUser(nUser(r.user ?? r))).catch(() => setUser(null)).finally(() => setReady(true));
  }, []);

  const login = async (email, password) => {
    await api.login(email, password);
    const r = await api.getCurrentUser();
    const u = nUser(r.user ?? r);
    setUser(u);
    return u;
  };
  const logout = async () => { try { await api.logout(); } catch { /* phiên có thể đã hết hạn */ } setUser(null); };

  return <Ctx.Provider value={{ user, ready, login, logout }}>{children}</Ctx.Provider>;
}

export function RequireAuth({ admin, children }) {
  const { user, ready } = useAuth();
  const loc = useLocation();
  if (!ready) return <Loading />;
  if (!user) return <Navigate to="/login" replace state={{ from: loc.pathname }} />;
  if (admin && !user.isAdmin) return <Navigate to="/dashboard" replace />;
  return children;
}
