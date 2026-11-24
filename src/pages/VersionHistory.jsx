import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api } from '../api/endpoints';
import { nDoc, nFolder, nVersion } from '../api/normalize';
import { useAuth } from '../auth/AuthContext';
import { Async, Badge, Button, PageHeader, StatusBadge, Table } from '../components/ui';
import { useToast } from '../components/Providers';
import { downloadVersion } from '../services/documents';
import { fmtDate } from '../utils/format';
import { useAsync } from '../utils/hooks';
import { canWrite } from './FolderDetail';

export default function VersionHistory() {
  const { folderId, documentId } = useParams();
  const { user } = useAuth();
  const toast = useToast();
  const [busyId, setBusyId] = useState(null);
  const folder = useAsync(() => api.getFolder(folderId).then(nFolder), [folderId]);
  const doc = useAsync(() => api.getDocument(documentId).then(nDoc), [documentId]);
  const vers = useAsync(() => api.listDocumentVersions(documentId).then((l) => l.map(nVersion)), [documentId]);

  async function download(v, name) {
    setBusyId(v.id);
    try { await downloadVersion({ versionId: v.id, fallbackName: name, userId: user.id }); }
    catch (e) { toast(e.message, 'error'); } finally { setBusyId(null); }
  }
  return (
    <Async state={folder}>
      {(f) => (
        <Async state={doc}>
          {(d) => (
            <Async state={vers}>
              {(rows) => {
                const w = canWrite(f.role);
                const latest = rows.find((v) => v.isCurrent) ?? rows[0];
                return (
                  <>
                    <PageHeader title="Version history" sub={<><Link to={`/folders/${f.id}`}>{f.name}</Link> / <Link to={`/folders/${f.id}/documents/${d.id}`}>{d.title}</Link></>} />
                    <p className="muted-note" style={{ fontSize: 13, marginBottom: 12 }}>All folder members can view the version history.</p>
                    {latest && <p style={{ marginBottom: 22 }}><Badge tone="ok">Latest: v{latest.number}</Badge></p>}
                    <Table rows={rows} empty="No versions found."
                      columns={[
                        { key: 'v', label: 'Version', width: '22%', render: (v) => `v${v.number}${v.isCurrent ? ' · Latest' : ''}` },
                        { key: 'updatedBy', label: 'Updated by', width: '24%' },
                        { key: 'createdAt', label: 'Date', width: '20%', render: (v) => fmtDate(v.createdAt) },
                        { key: 's', label: 'Status', width: '18%', render: (v) => (v.isCurrent ? <StatusBadge status="CURRENT" /> : <Badge tone="blue">Available</Badge>) },
                        { key: 'a', label: 'Action', width: '16%', stop: true, render: (v) => <button className="linkbtn" disabled={busyId === v.id} onClick={() => download(v, d.title)}>{busyId === v.id ? 'Preparing…' : 'Download'}</button> },
                      ]} />
                    <div className="panel" style={{ marginTop: 34, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', gap: 20, flexWrap: 'wrap' }}>
                      <div style={{ maxWidth: 640 }}>
                        <h3>Upload a new version</h3>
                        <p>{w ? 'Add an updated file. It becomes the current version and earlier versions stay available here.' : 'You have Viewer access, so you can view and download versions but not upload a new one.'}</p>
                      </div>
                      <Button variant={w ? 'primary' : undefined} disabled={!w} to={`/folders/${f.id}/upload?documentId=${d.id}`}>Upload new version</Button>
                    </div>
                    <p className="tbl-foot">Version history is always viewable; creating a new version is permission-controlled.</p>
                  </>
                );
              }}
            </Async>
          )}
        </Async>
      )}
    </Async>
  );
}
