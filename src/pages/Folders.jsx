import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/endpoints';
import { nFolder } from '../api/normalize';
import { useAuth } from '../auth/AuthContext';
import { Async, Button, Field, Modal, PageHeader, RoleBadge, Table } from '../components/ui';
import { useToast } from '../components/Providers';
import { signInitialFolderPolicy } from '../crypto';
import { activeKey, loadKeys, loadSigner } from '../services/vault';
import { fmtDate } from '../utils/format';
import { useAsync } from '../utils/hooks';

export default function Folders({ pickFor }) {
  const nav = useNavigate();
  const [creating, setCreating] = useState(false);
  const st = useAsync(() => api.listFolders().then((l) => l.map(nFolder)), []);
  const go = (f) => nav(pickFor === 'members' ? `/folders/${f.id}/members` : `/folders/${f.id}`);
  return (
    <>
      <PageHeader title={pickFor === 'members' ? 'Folder members' : 'Treatment folders'}
        sub={pickFor === 'members' ? 'Choose a folder to manage its members.' : 'Folders shared with your hospital account.'}>
        {!pickFor && <Button variant="primary" onClick={() => setCreating(true)}>+ Create folder</Button>}
      </PageHeader>
      <Async state={st}>
        {(rows) => <Table rows={rows} onRowClick={go} empty="No folders yet. Create one to start sharing documents."
          columns={[
            { key: 'name', label: 'Folder name / ID', width: '34%', render: (f) => `${f.name} · ${f.code}` },
            { key: 'treatmentRef', label: 'Treatment ref.', width: '14%' },
            { key: 'ownerName', label: 'Owner', width: '20%' },
            { key: 'role', label: 'Your role', width: '14%', render: (f) => <RoleBadge role={f.role} /> },
            { key: 'updatedAt', label: 'Last updated', width: '18%', render: (f) => fmtDate(f.updatedAt) },
          ]} />}
      </Async>
      {creating && <CreateFolder onClose={() => setCreating(false)} onCreated={(id) => nav(`/folders/${id}`)} />}
    </>
  );
}

function CreateFolder({ onClose, onCreated }) {
  const { user } = useAuth();
  const toast = useToast();
  const [f, setF] = useState({ name: '', treatmentRef: '', description: '' });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  async function submit(e) {
    e.preventDefault(); setBusy(true); setErr('');
    try {
      const folderId = crypto.randomUUID(); // client sinh folderId (UUID) theo contract
      const keys = await loadKeys();
      const signer = await loadSigner(user.id, keys);
      const enc = activeKey(keys, 'ENC');
      if (!enc) throw new Error('Set up your encryption and signing keys in Security & keys first.');
      // CONTRACT: nội dung policy đầu tiên (membership ban đầu) cần chốt với backend.
      const policy = { policyVersion: '1', members: [{ userId: user.id, role: 'OWNER', encryptionKeyId: enc.id }] };
      const signedInitialPolicy = await signInitialFolderPolicy({ folderId, policy, signer });
      await api.createFolder({ folderId, name: f.name.trim(), treatmentRef: f.treatmentRef.trim() || undefined, description: f.description.trim() || undefined, signedInitialPolicy });
      toast('Folder created.'); onCreated(folderId);
    } catch (x) { setErr(x.message); setBusy(false); }
  }
  return (
    <Modal title="Create folder" lead="You become the Owner. You can add colleagues afterwards." onClose={onClose}>
      <form onSubmit={submit}>
        <Field label="Folder name" htmlFor="fn"><input id="fn" className="input" required autoFocus placeholder="e.g. Cardiology follow-up" value={f.name} onChange={set('name')} /></Field>
        <Field label="Treatment reference" htmlFor="tr"><input id="tr" className="input" placeholder="e.g. TR-00481" value={f.treatmentRef} onChange={set('treatmentRef')} /></Field>
        <Field label="Description (optional)" htmlFor="fd"><textarea id="fd" className="textarea" value={f.description} onChange={set('description')} /></Field>
        {err && <p style={{ color: 'var(--danger)', fontSize: 12 }}>{err}</p>}
        <div className="form-actions"><Button onClick={onClose}>Cancel</Button><Button variant="primary" type="submit" disabled={busy || !f.name.trim()}>{busy ? 'Creating…' : 'Create folder'}</Button></div>
      </form>
    </Modal>
  );
}
