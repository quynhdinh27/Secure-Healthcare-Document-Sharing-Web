import { useState } from 'react';
import { api } from '../api/endpoints';
import { nEvent, nMember, nRotation, nSession, asList } from '../api/normalize';
import { useAuth } from '../auth/AuthContext';
import { signFolderPolicy } from '../crypto';
import { findFolderRotation } from '../services/rotation';
import { loadSigner } from '../services/vault';
import RotationAction from './RotationAction';
import { SESSION_LABEL } from '../utils/constants';
import { fmtDateTime } from '../utils/format';
import { useAsync } from '../utils/hooks';
import { Async, Button, Field, Modal, Notice, RoleBadge, StatusBadge, Table } from './ui';
import { useToast } from './Providers';

/* Banner trạng thái key session / rotation của folder */
export function KeySessionBanner({ folderId, tick = 0 }) {
  const s = useAsync(async () => {
    const state = await api.getCurrentKeySession(folderId).then(nSession).catch(() => ({ state: 'READY' }));
    const job = state.state === 'READY' ? null : await findFolderRotation(folderId).then((j) => j && nRotation(j)).catch(() => null);
    return { state: state.state, job };
  }, [folderId, tick]);
  const state = s.data?.state ?? 'READY';
  if (state === 'READY') return null;
  const job = s.data.job;
  return (
    <Notice tone="warn" action={job && <RotationAction job={job} onDone={s.reload} size="sm" />}>
      <b>Keys are changing.</b> {SESSION_LABEL[state] ?? state}
      {job && <> {job.total > 0 && <span style={{ marginLeft: 6 }}>({job.done}/{job.total} document versions)</span>}</>} Opening and uploading documents is paused until this finishes.
    </Notice>
  );
}

/* Tab Activity */
export function ActivityPanel({ folderId }) {
  const st = useAsync(() => api.listAuditEvents({ folderId }).then((l) => l.map(nEvent)), [folderId]);
  if (st.error?.status === 403) return <Notice>Folder activity is visible to the folder Owner.</Notice>;
  return (
    <Async state={st}>
      {(rows) => <Table rows={rows} empty="No activity recorded yet." columns={[
        { key: 'at', label: 'Date and time', width: '28%', render: (r) => fmtDateTime(r.at) },
        { key: 'label', label: 'Activity', width: '34%' },
        { key: 'item', label: 'Item', width: '38%' },
      ]} />}
    </Async>
  );
}

/* Quản lý thành viên: Owner ký policy context rồi mới gọi API đổi quyền */
export function MembersPanel({ folder, members, reload }) {
  const { user } = useAuth();
  const toast = useToast();
  const isOwner = folder.role === 'OWNER';
  const [modal, setModal] = useState(null); // {type:'add'|'role'|'revoke', member?}

  async function signedChange(action, target, call) {
    const signer = await loadSigner(user.id);
    const ctx = await api.createPolicyContext(folder.id, { action, ...target });
    const signedPolicy = await signFolderPolicy({ context: ctx, signer }); // Owner ký policy context (folder-policy/v1)
    await call({ contextId: ctx.contextId, signedPolicy });
    toast('Saved. Keys are being updated for this folder.');
    setModal(null); reload();
  }

  const cols = [
    { key: 'name', label: 'Member', width: '24%' },
    { key: 'email', label: 'Hospital email', width: '28%' },
    { key: 'role', label: 'Folder role', width: '16%', render: (m) => <RoleBadge role={m.role} /> },
    { key: 'status', label: 'Status', width: '14%', render: (m) => <StatusBadge status={m.status} /> },
    { key: 'a', label: 'Action', width: '18%', stop: true, render: (m) => (isOwner && m.role !== 'OWNER' ? (
      <span style={{ display: 'flex', gap: 14 }}>
        <button className="linkbtn" onClick={() => setModal({ type: 'role', member: m })}>Change role</button>
        <button className="linkbtn danger" onClick={() => setModal({ type: 'revoke', member: m })}>Revoke</button>
      </span>) : '—') },
  ];
  return (
    <>
      {isOwner && <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 14 }}><Button variant="primary" onClick={() => setModal({ type: 'add' })}>+ Add member</Button></div>}
      <Table rows={members} columns={cols} empty="No members yet." />
      <div className="panel" style={{ marginTop: 28, background: '#F8FAFC', border: '1px solid var(--line)' }}>
        <h3 style={{ color: 'var(--ink)' }}>Role permissions</h3>
        <p style={{ color: 'var(--muted)' }}>Owner: manage folder and members, delete documents · Editor: upload/update documents, rename folder · Viewer: view and download documents.</p>
      </div>
      {modal?.type === 'add' && <AddMember members={members} onClose={() => setModal(null)}
        onSubmit={(u, role) => signedChange('ADD_MEMBER', { targetUserId: u.userId, role }, (p) => api.addFolderMember(folder.id, { ...p, userId: u.userId, role }))} />}
      {modal?.type === 'role' && <ChangeRole member={modal.member} onClose={() => setModal(null)}
        onSubmit={(role) => signedChange('CHANGE_ROLE', { membershipId: modal.member.id, role }, (p) => api.changeFolderMemberRole(folder.id, modal.member.id, { ...p, role }))} />}
      {modal?.type === 'revoke' && <Revoke member={modal.member} onClose={() => setModal(null)}
        onSubmit={() => signedChange('REVOKE_MEMBER', { membershipId: modal.member.id }, (p) => api.revokeFolderMember(folder.id, modal.member.id, p))} />}
    </>
  );
}

function useSubmit(fn) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const run = async (...a) => { setBusy(true); setErr(''); try { await fn(...a); } catch (e) { setErr(e.message); setBusy(false); } };
  return { busy, err, run };
}

function AddMember({ members, onClose, onSubmit }) {
  const [q, setQ] = useState('');
  const [found, setFound] = useState(null);
  const [pick, setPick] = useState(null);
  const [role, setRole] = useState('VIEWER');
  const [searching, setSearching] = useState(false);
  const sub = useSubmit(() => onSubmit(pick, role));
  async function search(e) {
    e.preventDefault(); setSearching(true);
    try { setFound((await api.searchStaff(q)).filter((u) => !members.some((m) => m.userId === (u.userId ?? u.id)))); } finally { setSearching(false); }
  }
  return (
    <Modal title="Add member" lead="Find a colleague by name or hospital email. They will be able to open every version stored in this folder once keys are updated." onClose={onClose}>
      <form onSubmit={search} style={{ display: 'flex', gap: 8, marginBottom: 14 }}>
        <input className="input" aria-label="Name or hospital email" placeholder="name@hospital.org" value={q} onChange={(e) => setQ(e.target.value)} autoFocus />
        <Button type="submit" disabled={!q.trim() || searching}>Find</Button>
      </form>
      {found && (found.length === 0 ? <p className="muted-note" style={{ marginBottom: 14 }}>No matching active staff account.</p> : (
        <div role="radiogroup" aria-label="Search results" style={{ marginBottom: 14 }}>
          {found.map((u) => (
            <label key={u.userId ?? u.id} style={{ display: 'flex', gap: 10, padding: '8px 0', cursor: 'pointer', fontSize: 13 }}>
              <input type="radio" name="staff" disabled={u.hasKeys === false} onChange={() => setPick({ ...u, userId: u.userId ?? u.id })} />
              <span><b>{u.name ?? u.fullName}</b> <span style={{ color: 'var(--muted)' }}>{u.email}</span>{u.hasKeys === false && <span style={{ color: 'var(--warn)', marginLeft: 8 }}>Keys not set up yet</span>}</span>
            </label>
          ))}
        </div>
      ))}
      <Field label="Folder role" htmlFor="role">
        <select id="role" className="select" value={role} onChange={(e) => setRole(e.target.value)}>
          <option value="VIEWER">Viewer — view and download</option><option value="EDITOR">Editor — also upload and update</option>
        </select>
      </Field>
      {sub.err && <p style={{ color: 'var(--danger)', fontSize: 12 }}>{sub.err}</p>}
      <div className="form-actions"><Button onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!pick || sub.busy} onClick={() => sub.run()}>{sub.busy ? 'Signing…' : 'Add member'}</Button></div>
    </Modal>
  );
}

function ChangeRole({ member, onClose, onSubmit }) {
  const [role, setRole] = useState(member.role === 'EDITOR' ? 'VIEWER' : 'EDITOR');
  const sub = useSubmit(() => onSubmit(role));
  return (
    <Modal title="Change role" lead={`${member.name} · ${member.email}. The new role applies immediately.`} onClose={onClose}>
      <Field label="Folder role" htmlFor="nr"><select id="nr" className="select" value={role} onChange={(e) => setRole(e.target.value)}><option value="EDITOR">Editor</option><option value="VIEWER">Viewer</option></select></Field>
      {sub.err && <p style={{ color: 'var(--danger)', fontSize: 12 }}>{sub.err}</p>}
      <div className="form-actions"><Button onClick={onClose}>Cancel</Button><Button variant="primary" disabled={sub.busy} onClick={() => sub.run()}>{sub.busy ? 'Signing…' : 'Save role'}</Button></div>
    </Modal>
  );
}

function Revoke({ member, onClose, onSubmit }) {
  const sub = useSubmit(() => onSubmit());
  return (
    <Modal title="Revoke access" lead={`${member.name} will lose access to this folder immediately. Document keys are then replaced for the remaining members. Copies they already downloaded stay on their devices.`} onClose={onClose}>
      {sub.err && <p style={{ color: 'var(--danger)', fontSize: 12 }}>{sub.err}</p>}
      <div className="form-actions"><Button onClick={onClose}>Cancel</Button><Button variant="danger solid" disabled={sub.busy} onClick={() => sub.run()}>{sub.busy ? 'Signing…' : 'Revoke access'}</Button></div>
    </Modal>
  );
}

export const loadMembers = (folderId) => api.listFolderMembers(folderId).then((l) => asList(l).map(nMember));
