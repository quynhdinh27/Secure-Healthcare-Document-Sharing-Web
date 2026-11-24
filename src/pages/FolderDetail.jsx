import { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { api } from '../api/endpoints';
import { nDoc, nFolder } from '../api/normalize';
import { ActivityPanel, KeySessionBanner, MembersPanel, loadMembers } from '../components/FolderParts';
import { useReauth, useToast } from '../components/Providers';
import { Async, Badge, Button, Field, Modal, PageHeader, StatusBadge, Table } from '../components/ui';
import { fmtDate } from '../utils/format';
import { rememberFolder, useAsync } from '../utils/hooks';

export const canWrite = (role) => role === 'OWNER' || role === 'EDITOR';

export default function FolderDetail({ membersOnly }) {
  const { folderId } = useParams();
  const nav = useNavigate();
  const toast = useToast();
  const reauth = useReauth();
  const [tab, setTab] = useState(membersOnly ? 'members' : 'documents');
  const [tick, setTick] = useState(0);
  const [modal, setModal] = useState(null);
  rememberFolder(folderId);

  const folder = useAsync(() => api.getFolder(folderId).then(nFolder), [folderId]);
  const docs = useAsync(() => api.listFolderDocuments(folderId).then((l) => l.map(nDoc)), [folderId]);
  const mem = useAsync(() => loadMembers(folderId), [folderId]);

  async function remove() {
    if (!(await reauth())) return;
    try {
      const r = await api.deleteFolder(folderId);
      toast(r?.operationId ? 'Folder deleted. Cleanup is running in the background.' : 'Folder deleted.');
      nav('/folders');
    } catch (e) { toast(e.message, 'error'); }
  }

  return (
    <Async state={folder}>
      {(f) => (
        <>
          <PageHeader title={membersOnly ? 'Folder members' : f.name}
            sub={membersOnly ? `${f.name} · ${f.code}` : `${f.code}${f.treatmentRef ? ` · Treatment reference ${f.treatmentRef}` : ''}${f.ownerName ? ` · Owner: ${f.ownerName}` : ''}`}>
            {!membersOnly && canWrite(f.role) && <Button onClick={() => setModal('rename')}>Rename</Button>}
            {!membersOnly && f.role === 'OWNER' && <Button variant="danger" onClick={() => setModal('delete')}>Delete folder</Button>}
            {!membersOnly && canWrite(f.role) && <Button variant="primary" to={`/folders/${f.id}/upload`}>Upload document</Button>}
          </PageHeader>
          {!membersOnly && <p style={{ margin: '-12px 0 22px', display: 'flex', gap: 10 }}><StatusBadge status={f.status} /><Badge>Your role: {f.role[0] + f.role.slice(1).toLowerCase()}</Badge></p>}
          <KeySessionBanner folderId={f.id} tick={tick} />

          {!membersOnly && (
            <div className="tabs" role="tablist">
              {[['documents', `Documents (${docs.data?.length ?? '…'})`], ['members', `Members (${mem.data?.length ?? '…'})`], ['activity', 'Activity']].map(([k, l]) => (
                <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? 'on' : ''} onClick={() => setTab(k)}>{l}</button>
              ))}
            </div>
          )}

          {tab === 'documents' && !membersOnly && (
            <Async state={docs}>
              {(rows) => (
                <>
                  <Table rows={rows} onRowClick={(d) => nav(`/folders/${f.id}/documents/${d.id}`)} empty={canWrite(f.role) ? 'No documents yet. Upload the first one.' : 'No documents in this folder yet.'}
                    columns={[
                      { key: 'title', label: 'File name', width: '28%' },
                      { key: 'category', label: 'Category', width: '18%' },
                      { key: 'uploadedBy', label: 'Uploaded by', width: '20%' },
                      { key: 'v', label: 'Latest version', width: '20%', render: (d) => `${d.currentVersion ? `v${d.currentVersion}` : '—'} · ${fmtDate(d.updatedAt)}` },
                      { key: 'status', label: 'Status', width: '14%', render: (d) => <StatusBadge status={d.status} /> },
                    ]} />
                  {rows.length > 0 && <p className="tbl-foot">Select a document to view its details, download it or open its version history.</p>}
                </>
              )}
            </Async>
          )}
          {tab === 'members' && <Async state={mem}>{(rows) => <MembersPanel folder={f} members={rows} reload={() => { mem.reload(); setTick((t) => t + 1); }} />}</Async>}
          {tab === 'activity' && !membersOnly && <ActivityPanel folderId={f.id} />}

          {modal === 'rename' && <Rename folder={f} onClose={() => setModal(null)} onDone={() => { setModal(null); folder.reload(); }} />}
          {modal === 'delete' && (
            <Modal title="Delete this folder?" lead="The folder and every document and version in it will be deleted. This can’t be undone." onClose={() => setModal(null)}>
              <div className="form-actions"><Button onClick={() => setModal(null)}>Cancel</Button><Button variant="danger solid" onClick={() => { setModal(null); remove(); }}>Delete folder</Button></div>
            </Modal>
          )}
        </>
      )}
    </Async>
  );
}

function Rename({ folder, onClose, onDone }) {
  const toast = useToast();
  const [name, setName] = useState(folder.name);
  const [desc, setDesc] = useState(folder.description ?? '');
  const [busy, setBusy] = useState(false);
  async function save(e) {
    e.preventDefault(); setBusy(true);
    try { await api.updateFolder(folder.id, { name: name.trim(), description: desc.trim() }); toast('Folder updated.'); onDone(); }
    catch (x) { toast(x.message, 'error'); setBusy(false); }
  }
  return (
    <Modal title="Rename folder" lead="Owners and Editors can change the name and description. Roles and members don’t change." onClose={onClose}>
      <form onSubmit={save}>
        <Field label="Folder name" htmlFor="rn"><input id="rn" className="input" required autoFocus value={name} onChange={(e) => setName(e.target.value)} /></Field>
        <Field label="Description" htmlFor="rd"><textarea id="rd" className="textarea" value={desc} onChange={(e) => setDesc(e.target.value)} /></Field>
        <div className="form-actions"><Button onClick={onClose}>Cancel</Button><Button variant="primary" type="submit" disabled={busy || !name.trim()}>Save changes</Button></div>
      </form>
    </Modal>
  );
}

