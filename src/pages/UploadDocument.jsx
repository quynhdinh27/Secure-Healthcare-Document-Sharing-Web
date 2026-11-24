import { useRef, useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { api } from '../api/endpoints';
import { nDoc, nFolder } from '../api/normalize';
import { useAuth } from '../auth/AuthContext';
import { Async, Button, Field, Notice, PageHeader } from '../components/ui';
import { useToast } from '../components/Providers';
import { uploadNewDocument, uploadNewVersion } from '../services/documents';
import { ACCEPT, CATEGORIES, MAX_FILE_BYTES } from '../utils/constants';
import { fmtSize } from '../utils/format';
import { useAsync } from '../utils/hooks';
import { canWrite } from './FolderDetail';

/** Dùng cho cả upload tài liệu mới và upload version mới (?documentId=...). */
export default function UploadDocument() {
  const { folderId } = useParams();
  const [sp] = useSearchParams();
  const documentId = sp.get('documentId');
  const { user } = useAuth();
  const nav = useNavigate();
  const toast = useToast();
  const input = useRef(null);
  const folder = useAsync(() => api.getFolder(folderId).then(nFolder), [folderId]);
  const doc = useAsync(() => (documentId ? api.getDocument(documentId).then(nDoc) : Promise.resolve(null)), [documentId]);

  const [title, setTitle] = useState('');
  const [category, setCategory] = useState('');
  const [file, setFile] = useState(null);
  const [over, setOver] = useState(false);
  const [step, setStep] = useState('');
  const [err, setErr] = useState('');

  const pickFile = (f) => {
    setErr('');
    if (!f) return;
    if (!/\.(pdf|jpe?g|png)$/i.test(f.name)) return setErr('Choose a PDF, JPG or PNG file.');
    if (f.size > MAX_FILE_BYTES) return setErr(`This file is larger than ${fmtSize(MAX_FILE_BYTES)}.`);
    setFile(f);
    if (!documentId && !title.trim()) setTitle(f.name);
  };

  async function submit(e) {
    e.preventDefault(); setErr('');
    try {
      if (documentId) {
        await uploadNewVersion({ folderId, documentId, baseVersionId: doc.data.currentVersionId, file, userId: user.id, onStep: setStep });
        toast('New version uploaded. It is now the current version.');
        nav(`/folders/${folderId}/documents/${documentId}`);
      } else {
        const r = await uploadNewDocument({ folderId, title: title.trim(), category, file, userId: user.id, onStep: setStep });
        toast('Document uploaded.');
        nav(r?.documentId ? `/folders/${folderId}/documents/${r.documentId}` : `/folders/${folderId}`);
      }
    } catch (x) { setErr(x.message); setStep(''); }
  }

  return (
    <Async state={folder}>
      {(f) => !canWrite(f.role) ? (
        <><PageHeader title="Upload document" /><Notice tone="warn">Your Viewer access doesn’t allow uploads. You can still view and download documents.</Notice></>
      ) : (
        <>
          <PageHeader title={documentId ? 'Upload new version' : 'Upload document'}
            sub={documentId ? `Add a new version of ${doc.data?.title ?? 'this document'}` : `Add a document to ${f.name} · ${f.code}`} />
          <form className="card" style={{ padding: 40, maxWidth: 1120 }} onSubmit={submit}>
            <h2 style={{ marginBottom: 22 }}>{documentId ? 'New version' : 'Document information'}</h2>
            {!documentId && (
              <div className="grid2">
                <Field label="Document title" htmlFor="t"><input id="t" className="input" required placeholder="e.g. Discharge summary" value={title} onChange={(e) => setTitle(e.target.value)} /></Field>
                <Field label="Document category" htmlFor="c" help={CATEGORIES.join(' · ')}>
                  <select id="c" className="select" required value={category} onChange={(e) => setCategory(e.target.value)}>
                    <option value="">Select a category</option>{CATEGORIES.map((c) => <option key={c}>{c}</option>)}
                  </select>
                </Field>
              </div>
            )}
            <Field label="Choose file">
              <div className={`dropzone ${over ? 'over' : ''}`} role="button" tabIndex={0}
                onClick={() => input.current.click()} onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && input.current.click()}
                onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)}
                onDrop={(e) => { e.preventDefault(); setOver(false); pickFile(e.dataTransfer.files[0]); }}>
                {file ? <><b>{file.name}</b><span>{fmtSize(file.size)} · Select to change</span></> : <><b>Drag a file here or browse your device</b><span>PDF, JPG or PNG · Select one file</span></>}
                <input ref={input} type="file" accept={ACCEPT} hidden onChange={(e) => pickFile(e.target.files[0])} />
              </div>
            </Field>
            <p className="muted-note">The system will securely prepare your document automatically.</p>
            {err && <div style={{ marginTop: 16 }}><Notice tone="danger">{err}</Notice></div>}
            {step && <p className="muted-note" style={{ marginTop: 14 }} role="status"><span className="spinner" /> {step}</p>}
            <div className="form-actions">
              <Button onClick={() => nav(-1)} disabled={!!step}>Cancel</Button>
              <Button variant="primary" type="submit" disabled={!file || !!step || (!documentId && (!title.trim() || !category)) || (documentId && !doc.data)}>
                {step ? 'Uploading…' : documentId ? 'Upload version' : 'Upload document'}
              </Button>
            </div>
          </form>
        </>
      )}
    </Async>
  );
}
