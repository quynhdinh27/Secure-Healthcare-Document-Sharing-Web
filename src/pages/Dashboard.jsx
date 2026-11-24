import { Link, useNavigate } from 'react-router-dom';
import { api } from '../api/endpoints';
import { nKey } from '../api/normalize';
import { isActiveJob } from '../services/rotation';
import { useAuth } from '../auth/AuthContext';
import { Async, Notice, PageHeader, RoleBadge, Table } from '../components/ui';
import { fmtDate } from '../utils/format';
import { useAsync } from '../utils/hooks';

const QUICK = [
  { to: '/folders', title: 'Treatment folders', text: 'Open shared treatment folders' },
  { to: '/security', title: 'Security & keys', text: 'Manage your device keys and signing identity' },
  { to: '/audit', title: 'My activity', text: 'Review actions performed by your account' },
];

export default function Dashboard() {
  const { user } = useAuth();
  const nav = useNavigate();
  const sum = useAsync(() => api.getDashboardSummary(), []);
  const keys = useAsync(() => api.listMyKeys().then((l) => l.map(nKey)).catch(() => null), []);
  const jobs = useAsync(() => api.listRotations().then((l) => l.filter(isActiveJob)).catch(() => []), []);
  const missing = keys.data && !['ENC', 'SIGN'].every((p) => keys.data.some((k) => k.purpose === p && k.status === 'ACTIVE'));

  return (
    <>
      <PageHeader title="Dashboard" sub={`Welcome back, ${user.name}. Here is your workspace at a glance.`} />
      {missing && <Notice tone="warn" action={<Link className="btn sm primary" to="/security">Set up keys</Link>}>You need an encryption key and a signing key before you can upload or open documents.</Notice>}
      {jobs.data?.length > 0 && <Notice tone="warn" action={<Link className="btn sm primary" to="/security/rotation-audit">View progress</Link>}>Document keys are being updated in {jobs.data.length} folder{jobs.data.length > 1 ? 's' : ''}. Those documents stay locked until each update finishes.</Notice>}
      <Async state={sum}>
        {(s) => (
          <>
            <div className="grid3">
              <div className="card stat"><div className="label">Accessible folders</div><div className="value">{s.folderCount}</div><div className="hint">Folders you can access</div></div>
              <div className="card stat"><div className="label">Documents</div><div className="value">{s.documentCount}</div><div className="hint">Available records</div></div>
              {s.activityCount != null && <div className="card stat"><div className="label">Recent activity</div><div className="value">{s.activityCount}</div><div className="hint">Actions this month</div></div>}
            </div>
            <h2 className="section-title">Quick access</h2>
            <div className="grid3">
              {QUICK.map((q) => <Link key={q.to} to={q.to} className="card quick"><h3>{q.title}</h3><p>{q.text}</p><span>Open →</span></Link>)}
            </div>
            <h2 className="section-title">Recently updated folders</h2>
            <Table rowKey={(r) => r.folderId} rows={s.recentFolders ?? []} onRowClick={(r) => nav(`/folders/${r.folderId}`)} empty="You don’t have any folders yet."
              columns={[
                { key: 'name', label: 'Folder name / ID', width: '50%' },
                { key: 'role', label: 'Your role', width: '20%', render: (r) => <RoleBadge role={r.role} /> },
                { key: 'updatedAt', label: 'Last updated', width: '30%', render: (r) => fmtDate(r.updatedAt) },
              ]} />
          </>
        )}
      </Async>
    </>
  );
}
