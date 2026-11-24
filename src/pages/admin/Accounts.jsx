import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../api/endpoints';
import { nUser } from '../../api/normalize';
import { Async, Button, Field, Modal, PageHeader, StatusBadge, Table } from '../../components/ui';
import { useToast } from '../../components/Providers';
import { fmtDate } from '../../utils/format';
import { useAsync } from '../../utils/hooks';

export default function Accounts() {
  const nav = useNavigate();
  const [creating, setCreating] = useState(false);
  const st = useAsync(() => api.listAdminUsers({ pageSize: 100 }).then((l) => l.map(nUser)), []);
  return (
    <>
      <PageHeader title="Hospital accounts" sub="Manage staff accounts for the MedShare application.">
        <Button variant="primary" onClick={() => setCreating(true)}>+ Create account</Button>
      </PageHeader>
      <Async state={st}>
        {(rows) => <Table rows={rows} onRowClick={(u) => nav(`/admin/accounts/${u.id}`)} empty="No accounts yet." columns={[
          { key: 'staffId', label: 'Staff ID', width: '14%' },
          { key: 'name', label: 'Name', width: '22%' },
          { key: 'email', label: 'Hospital email', width: '28%' },
          { key: 'status', label: 'Status', width: '16%', render: (u) => <StatusBadge status={u.status} /> },
          { key: 'lastSignIn', label: 'Last sign-in', width: '20%', render: (u) => fmtDate(u.lastSignIn) },
        ]} />}
      </Async>
      {creating && <CreateAccount onClose={() => setCreating(false)} onDone={() => { setCreating(false); st.reload(); }} />}
    </>
  );
}

// CONTRACT: payload tạo tài khoản + cách cấp thông tin đăng nhập ban đầu chưa chốt (mục 11 của tài liệu API).
function CreateAccount({ onClose, onDone }) {
  const toast = useToast();
  const [f, setF] = useState({ staffId: '', name: '', email: '', department: '' });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  async function submit(e) {
    e.preventDefault(); setBusy(true); setErr('');
    try { await api.createAdminUser(f); toast('Account created.'); onDone(); } catch (x) { setErr(x.message); setBusy(false); }
  }
  return (
    <Modal title="Create account" lead="The staff member signs in with their hospital email." onClose={onClose}>
      <form onSubmit={submit}>
        <Field label="Staff ID" htmlFor="s"><input id="s" className="input" required autoFocus value={f.staffId} onChange={set('staffId')} placeholder="ST-00200" /></Field>
        <Field label="Full name" htmlFor="n"><input id="n" className="input" required value={f.name} onChange={set('name')} /></Field>
        <Field label="Hospital email" htmlFor="e"><input id="e" type="email" className="input" required value={f.email} onChange={set('email')} placeholder="name@hospital.org" /></Field>
        <Field label="Department" htmlFor="d"><input id="d" className="input" value={f.department} onChange={set('department')} /></Field>
        {err && <p style={{ color: 'var(--danger)', fontSize: 12 }}>{err}</p>}
        <div className="form-actions"><Button onClick={onClose}>Cancel</Button><Button variant="primary" type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create account'}</Button></div>
      </form>
    </Modal>
  );
}
