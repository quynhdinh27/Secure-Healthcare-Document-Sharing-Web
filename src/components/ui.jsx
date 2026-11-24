import { useEffect } from 'react';
import { Link } from 'react-router-dom';
import { fmtDate } from '../utils/format';

export const cx = (...a) => a.filter(Boolean).join(' ');

export function Badge({ tone, children }) { return <span className={cx('badge', tone)}>{children}</span>; }
export function RoleBadge({ role }) {
  const r = String(role || '').toUpperCase();
  const tone = r === 'OWNER' ? 'blue' : r === 'EDITOR' ? 'ok' : '';
  return <Badge tone={tone}>{r ? r[0] + r.slice(1).toLowerCase() : '—'}</Badge>;
}
export function StatusBadge({ status }) {
  const s = String(status || '').toUpperCase();
  const map = {
    ACTIVE: ['ok', 'Active'], AVAILABLE: ['ok', 'Available'], CURRENT: ['ok', 'Current'], SUCCESS: ['ok', 'Success'], INACTIVE: ['danger', 'Inactive'],
    FAILED: ['danger', 'Failed'], REVOKED: ['danger', 'Revoked'], RETIRED: ['', 'Replaced'], PENDING_VERIFICATION: ['warn', 'Pending'],
    COMPLETED: ['ok', 'Completed'], COMMITTED: ['ok', 'Done'], IN_PROGRESS: ['blue', 'In progress'], STAGED: ['blue', 'Re-encrypted'], PENDING: ['', 'Waiting'],
    WAITING_FOR_CLIENT: ['warn', 'Needs re-encryption'], WAITING_FOR_OWNER: ['warn', 'Needs Owner approval'], WAITING_FOR_KEY: ['warn', 'Waiting for new key'],
  };
  const [tone, label] = map[s] ?? ['', s ? s[0] + s.slice(1).toLowerCase() : '—'];
  return <Badge tone={tone}>{label}</Badge>;
}

export function PageHeader({ title, sub, children }) {
  return (
    <header className="page-head">
      <div><h1>{title}</h1>{sub && <p className="sub">{sub}</p>}</div>
      {children && <div className="head-actions">{children}</div>}
    </header>
  );
}

export function Button({ variant, size, block, to, children, ...p }) {
  const c = cx('btn', variant, size, block && 'block');
  return to && !p.disabled ? <Link className={c} to={to}>{children}</Link> : <button type="button" className={c} {...p}>{children}</button>;
}

export function Notice({ tone, children, action }) {
  return <div className={cx('notice', tone)} role={tone === 'danger' ? 'alert' : 'status'}><div className="grow">{children}</div>{action}</div>;
}

export function Loading({ label = 'Loading…' }) { return <div className="center"><span className="spinner" aria-hidden /><span>{label}</span></div>; }
export function ErrorState({ error, onRetry }) {
  return <Notice tone="danger" action={onRetry && <Button size="sm" onClick={onRetry}>Try again</Button>}>{error?.message || 'Something went wrong.'}</Notice>;
}
/** Hiển thị loading/error/dữ liệu cho một kết quả useAsync. */
export function Async({ state, children }) {
  if (state.loading && !state.data) return <Loading />;
  if (state.error) return <ErrorState error={state.error} onRetry={state.reload} />;
  return children(state.data);
}

export function Table({ columns, rows, onRowClick, empty = 'Nothing here yet.', rowKey = (r) => r.id }) {
  return (
    <div className="tbl-wrap">
      <table className="tbl">
        <colgroup>{columns.map((c) => <col key={c.key} style={{ width: c.width }} />)}</colgroup>
        <thead><tr>{columns.map((c) => <th key={c.key}>{c.label}</th>)}</tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={rowKey(r)} className={onRowClick ? 'click' : undefined} tabIndex={onRowClick ? 0 : undefined}
              onClick={() => onRowClick?.(r)} onKeyDown={(e) => e.key === 'Enter' && onRowClick?.(r)}>
              {columns.map((c) => <td key={c.key} title={typeof c.render === 'undefined' && typeof r[c.key] === 'string' ? r[c.key] : undefined} onClick={c.stop ? (e) => e.stopPropagation() : undefined}>{c.render ? c.render(r) : r[c.key] ?? '—'}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length === 0 && <div className="empty">{empty}</div>}
    </div>
  );
}

export function Modal({ title, lead, onClose, children }) {
  useEffect(() => {
    const k = (e) => e.key === 'Escape' && onClose();
    document.addEventListener('keydown', k);
    return () => document.removeEventListener('keydown', k);
  }, [onClose]);
  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title}>
        <h2>{title}</h2>{lead && <p className="lead">{lead}</p>}
        {children}
      </div>
    </div>
  );
}

export function Field({ label, help, children, htmlFor }) {
  return <div className="field"><label htmlFor={htmlFor}>{label}</label>{children}{help && <div className="help">{help}</div>}</div>;
}

export const dateCell = (v) => fmtDate(v);

export function Progress({ done, total }) {
  const pct = total ? Math.round((done / total) * 100) : 0;
  return (
    <span className="progress" title={`${done} of ${total} document versions`}>
      <span className="bar" role="progressbar" aria-valuenow={done} aria-valuemin={0} aria-valuemax={total}><i style={{ width: `${pct}%` }} /></span>
      <b>{done}/{total}</b>
    </span>
  );
}
