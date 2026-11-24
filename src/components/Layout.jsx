import { Link, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';

const STAFF = [
  { to: '/dashboard', label: 'Dashboard', on: (p) => p.startsWith('/dashboard') },
  { to: '/folders', label: 'Treatment folders', on: (p) => p.startsWith('/folders') && !p.endsWith('/members') },
  { to: '/members', label: 'Members', on: (p) => p === '/members' || p.endsWith('/members') },
  { to: '/security', label: 'Security & keys', on: (p) => p.startsWith('/security') },
  { to: '/audit', label: 'Audit log', on: (p) => p.startsWith('/audit') },
];
const ADMIN = [
  { to: '/admin/accounts', label: 'Accounts', on: (p) => p.startsWith('/admin/accounts') },
  { to: '/admin/activity', label: 'Admin activity', on: (p) => p.startsWith('/admin/activity') },
];

export default function Layout({ children }) {
  const { user, logout } = useAuth();
  const { pathname } = useLocation();
  const inAdmin = pathname.startsWith('/admin');
  const items = inAdmin ? ADMIN : [...STAFF, ...(user.isAdmin ? [{ to: '/admin/accounts', label: 'Admin console', on: () => false }] : [])];
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><b>MEDSHARE</b><span>Secure medical workspace</span></div>
        <nav className="nav" aria-label="Main">
          {items.map((i) => <Link key={i.to + i.label} to={i.to} className={i.on(pathname) ? 'active' : ''} aria-current={i.on(pathname) ? 'page' : undefined}>{i.label}</Link>)}
        </nav>
        <div className="sidebar-foot">
          <b>{inAdmin ? 'Hospital Administrator' : user.name}</b>
          <span>{inAdmin ? 'System administration' : 'Hospital staff'}</span>
          <div><button onClick={logout}>Sign out</button></div>
        </div>
      </aside>
      <main className="main">{children ?? <Outlet />}</main>
    </div>
  );
}
