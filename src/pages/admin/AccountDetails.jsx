import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api } from '../../api/endpoints';
import { nUser } from '../../api/normalize';
import { Async, Button, Field, Modal, PageHeader, StatusBadge } from '../../components/ui';
import { useToast } from '../../components/Providers';
import { fmtDate, fmtDateTime } from '../../utils/format';
import { useAsync } from '../../utils/hooks';

export default function AccountDetails() {
  const { userId } = useParams();
  const toast = useToast();
  const [modal, setModal] = useState(null);
  const st = useAsync(() => api.getAdminUser(userId).then(nUser), [userId]);

  async function toggle(u) {
    const next = u.status === 'ACTIVE' ? 'INACTIVE' : 'ACTIVE';
    try { await api.updateAdminUserStatus(u.id, { status: next }); toast(next === 'ACTIVE' ? 'Account reactivated.' : 'Account deactivated.'); setModal(null); st.reload(); }
    catch (e) { toast(e.message, 'error'); setModal(null); }
  }
  return (
    <Async state={st}>
      {(u) => {
        const active = u.status === 'ACTIVE';
        return (
          <>
            <PageHeader title="Account details" sub={<><Link to="/admin/accounts">Staff directory</Link> / {u.staffId}</>} />
            <div className="detail-grid" style={{ gridTemplateColumns: 'minmax(0,1.6fr) minmax(0,1fr)' }}>
              <section className="card" style={{ padding: '30px 40px' }}>
                <h2 style={{ fontSize: 22 }}>{u.name}</h2>
                <div style={{ margin: '14px 0 26px' }}><StatusBadge status={u.status} /></div>
                <dl style={{ margin: 0 }}>
                  {[['Staff ID', u.staffId], ['Hospital email', u.email], ['Department', u.department], ['Created on', fmtDate(u.createdAt)], ['Last sign-in', fmtDateTime(u.lastSignIn)]]
                    .map(([k, v]) => <div className="kv" key={k}><dt>{k}</dt><dd>{v || '—'}</dd></div>)}
                </dl>
              </section>
              <div className="stack">
                <aside className="card stack" style={{ padding: 30 }}>
                  <h2>Account actions</h2>
                  <Button block onClick={() => setModal('edit')}>Edit profile</Button>
                  <Button block variant={active ? 'danger' : 'primary'} onClick={() => setModal('status')}>{active ? 'Deactivate account' : 'Reactivate account'}</Button>
                  <p className="muted-note">{active ? 'Deactivation prevents future sign-ins and access to protected application areas.' : 'Reactivation lets this person sign in again.'}</p>
                </aside>
                <div className="panel"><h3>Folder permissions</h3><p>Folder roles are managed by each folder Owner, not by the admin.</p></div>
              </div>
            </div>
            {modal === 'status' && (
              <Modal title={active ? 'Deactivate this account?' : 'Reactivate this account?'} lead={active ? `${u.name} will be signed out and can’t sign in until the account is reactivated.` : `${u.name} will be able to sign in again.`} onClose={() => setModal(null)}>
                <div className="form-actions"><Button onClick={() => setModal(null)}>Cancel</Button><Button variant={active ? 'danger solid' : 'primary'} onClick={() => toggle(u)}>{active ? 'Deactivate' : 'Reactivate'}</Button></div>
              </Modal>
            )}
            {modal === 'edit' && <Edit u={u} onClose={() => setModal(null)} onDone={() => { setModal(null); st.reload(); }} />}
          </>
        );
      }}
    </Async>
  );
}

function Edit({ u, onClose, onDone }) {
  const toast = useToast();
  const [name, setName] = useState(u.name ?? '');
  const [department, setDepartment] = useState(u.department ?? '');
  async function save(e) {
    e.preventDefault();
    try { await api.updateAdminUser(u.id, { name: name.trim(), department: department.trim() }); toast('Profile updated.'); onDone(); } catch (x) { toast(x.message, 'error'); }
  }
  return (
    <Modal title="Edit profile" onClose={onClose}>
      <form onSubmit={save}>
        <Field label="Full name" htmlFor="en"><input id="en" className="input" required value={name} onChange={(e) => setName(e.target.value)} /></Field>
        <Field label="Department" htmlFor="ed"><input id="ed" className="input" value={department} onChange={(e) => setDepartment(e.target.value)} /></Field>
        <div className="form-actions"><Button onClick={onClose}>Cancel</Button><Button variant="primary" type="submit">Save changes</Button></div>
      </form>
    </Modal>
  );
}
