import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api } from '../api/endpoints';
import { nDoc, nFolder } from '../api/normalize';
import { useAuth } from '../auth/AuthContext';
import { Async, Badge, Button, Field, Modal, PageHeader, StatusBadge } from '../components/ui';
import { useToast } from '../components/Providers';
import { downloadVersion } from '../services/documents';
import { fmtType as fmtT } from '../utils/format';
import { CATEGORIES } from '../utils/constants';
import { fmtDate, fmtSize, fmtType } from '../utils/format';
import { rememberFolder, useAsync } from '../utils/hooks';
import { canWrite } from './FolderDetail';

export default function DocumentDetails() {
  const { folderId, documentId } = useParams();
  const { user } = useAuth();
  const nav = useNavigate();
  const toast = useToast();
  rememberFolder(folderId);
  const folder = useAsync(() => api.getFolder(folderId).then(nFolder), [folderId]);
  const doc = useAsync(() => api.getDocument(documentId).then(nDoc), [documentId]);
  const [busy, setBusy] = useState(false);
  const [integrity, setIntegrity] = useState(null); // null = chưa kiểm tra
  const [modal, setModal] = useState(null);

  async function download(d) {
    setBusy(true);
    try { setIntegrity(await downloadVersion({ versionId: d.currentVersionId, fallbackName: d.title, userId: user.id })); }
    catch (e) { setIntegrity({ ok: false }); toast(e.message, 'error'); }
    finally { setBusy(false); }
  }
  async function remove() {
    try { await api.deleteDocument(documentId); toast('Document deleted.'); nav(`/folders/${folderId}`); }
    catch (e) { toast(e.message, 'error'); setModal(null); }
  }

  return (
    <Async state={doc}>
      {(d) => (
        <Async state={folder}>
          {(f) => {
            const w = canWrite(f.role);
            return (
              <>
                <PageHeader title="Document details" sub={<><Link to={`/folders/${f.id}`}>{f.name}</Link> / {d.title}</>} />
                <div className="detail-grid">
                  <section className="card" style={{ padding: '30px 40px' }}>
                    <h2 style={{ fontSize: 22 }}>{d.title}</h2>
                    <div style={{ margin: '14px 0 30px' }}><StatusBadge status={d.status} /></div>
                    <h3 style={{ fontSize: 16, marginBottom: 6 }}>File information</h3>
                    <dl style={{ margin: 0 }}>
                      {[['Category', d.category], ['File type', integrity?.metadata ? fmtT(integrity.metadata.mimeType, integrity.metadata.fileName) : fmtType(d.mimeType, d.title)], ['File size', fmtSize(integrity?.metadata?.size ?? d.size)], ['Uploaded by', d.uploadedBy], ['Uploaded on', fmtDate(d.createdAt)], ['Current version', d.currentVersion ? `v${d.currentVersion}` : '—']]
                        .map(([k, v]) => <div className="kv" key={k}><dt>{k}</dt><dd>{v ?? '—'}</dd></div>)}
                    </dl>
                  </section>
                  <aside className="card stack" style={{ padding: 30 }}>
                    <h2>Document actions</h2>
                    <Button variant="primary" block disabled={busy || !d.currentVersionId} onClick={() => download(d)}>{busy ? 'Preparing…' : 'Download document'}</Button>
                    <Button block to={`/folders/${f.id}/documents/${d.id}/versions`}>View version history</Button>
                    <div className="divider" />
                    <h3>Update document</h3>
                    <p className="muted-note">Owner / Editor can upload a new version.</p>
                    <Button block disabled={!w} to={`/folders/${f.id}/upload?documentId=${d.id}`}>Upload new version</Button>
                    {!w && <p className="muted-note">Disabled for Viewer. Only users with update permission can create a version.</p>}
                    {w && <Button block onClick={() => setModal('edit')}>Edit title and category</Button>}
                    {f.role === 'OWNER' && <Button block variant="danger" onClick={() => setModal('delete')}>Delete document</Button>}
                    <div className="divider" />
                    <h3>File integrity</h3>
                    <p>{integrity == null ? <Badge>Checked when you download</Badge> : integrity.ok ? <Badge tone="ok">Check passed</Badge> : <Badge tone="danger">Check failed</Badge>}</p>
                    <p className="muted-note">{integrity?.ok ? 'Author signature, key policy and file contents were verified on this device.' : 'Download the file to your device to view it.'}</p>
                  </aside>
                </div>
                {modal === 'edit' && <EditMeta doc={d} onClose={() => setModal(null)} onDone={() => { setModal(null); doc.reload(); }} />}
                {modal === 'delete' && (
                  <Modal title="Delete this document?" lead="All versions of this document will be deleted. This can’t be undone." onClose={() => setModal(null)}>
                    <div className="form-actions"><Button onClick={() => setModal(null)}>Cancel</Button><Button variant="danger solid" onClick={remove}>Delete document</Button></div>
                  </Modal>
                )}
              </>
            );
          }}
        </Async>
      )}
    </Async>
  );
}

function EditMeta({ doc, onClose, onDone }) {
  const toast = useToast();
  const [title, setTitle] = useState(doc.title);
  const [category, setCategory] = useState(doc.category ?? '');
  async function save(e) {
    e.preventDefault();
    try { await api.updateDocumentMetadata(doc.id, { title: title.trim(), category }); toast('Document updated.'); onDone(); }
    catch (x) { toast(x.message, 'error'); }
  }
  return (
    <Modal title="Edit title and category" lead="These details are visible to folder members. File contents change only by uploading a new version." onClose={onClose}>
      <form onSubmit={save}>
        <Field label="Document title" htmlFor="et"><input id="et" className="input" required value={title} onChange={(e) => setTitle(e.target.value)} /></Field>
        <Field label="Document category" htmlFor="ec"><select id="ec" className="select" value={category} onChange={(e) => setCategory(e.target.value)}>{CATEGORIES.map((c) => <option key={c}>{c}</option>)}</select></Field>
        <div className="form-actions"><Button onClick={onClose}>Cancel</Button><Button variant="primary" type="submit" disabled={!title.trim()}>Save changes</Button></div>
      </form>
    </Modal>
  );
}
