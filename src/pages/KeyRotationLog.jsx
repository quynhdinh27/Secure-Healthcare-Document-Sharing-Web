import { useState } from 'react';
import { api } from '../api/endpoints';
import { nEvent, nRotation } from '../api/normalize';
import RotationAction from '../components/RotationAction';
import { Async, Button, Modal, PageHeader, Progress, StatusBadge, Table } from '../components/ui';
import { ellipsisId, fmtDateTime } from '../utils/format';
import { useAsync } from '../utils/hooks';

// Key rotation log = nhật ký riêng cho KHÓA và việc phân phối/đổi DEK: job, tiến độ, từng item, kết quả.
// Khác Audit log (hành động bảo mật toàn hệ thống: ai làm gì, khi nào).
const keyTypeLabel = (t) => (String(t).toUpperCase().startsWith('ENC') ? 'Encryption key' : t ? 'Signing key' : '—');

export default function KeyRotationLog() {
  const [open, setOpen] = useState(null);
  const jobs = useAsync(() => api.listRotations().then((l) => l.map(nRotation)), []);
  const events = useAsync(() => api.listAuditEvents({ category: 'KEY' }).then((l) => l.map(nEvent)), []);
  const reload = () => { jobs.reload(); events.reload(); };
  return (
    <>
      <PageHeader title="Key rotation log" sub="Tracks key changes and how document keys were replaced and shared again: jobs, progress, each item and result.">
        <Button to="/security">Back to Security & keys</Button>
      </PageHeader>

      <h2 className="section-title" style={{ marginTop: 0 }}>Document key updates</h2>
      <Async state={jobs}>
        {(rows) => <Table rows={rows} onRowClick={(j) => setOpen(j.id)} empty="No document key updates yet. They start after a key compromise or a change in folder members." columns={[
          { key: 'createdAt', label: 'Started', width: '17%', render: (j) => fmtDateTime(j.createdAt) },
          { key: 'folder', label: 'Folder', width: '23%' },
          { key: 'reasonLabel', label: 'Reason', width: '22%' },
          { key: 'p', label: 'Progress', width: '16%', render: (j) => <Progress done={j.status === 'COMPLETED' ? j.total : j.done} total={j.total} /> },
          { key: 's', label: 'Status', width: '22%', render: (j) => <StatusBadge status={j.status} /> },
        ]} />}
      </Async>

      <h2 className="section-title">Key events</h2>
      <Async state={events}>
        {(rows) => <Table rows={rows} empty="No key events recorded yet." columns={[
          { key: 'at', label: 'Date and time', width: '22%', render: (r) => fmtDateTime(r.at) },
          { key: 'keyType', label: 'Key type', width: '16%', render: (r) => keyTypeLabel(r.keyType) },
          { key: 'keyId', label: 'Key ID', width: '24%', render: (r) => ellipsisId(r.keyId) },
          { key: 'label', label: 'Event', width: '24%' },
          { key: 'result', label: 'Result', width: '14%', render: (r) => <StatusBadge status={r.result ?? 'SUCCESS'} /> },
        ]} />}
      </Async>
      <p className="tbl-foot">Private key material is never shown here. For who did what across folders, see the Audit log.</p>
      {open && <JobDetail id={open} onClose={() => setOpen(null)} onChanged={reload} />}
    </>
  );
}

function JobDetail({ id, onClose, onChanged }) {
  const st = useAsync(() => api.getRotation(id).then(nRotation), [id]);
  const refresh = () => { st.reload(); onChanged(); };
  return (
    <Modal title="Key update details" onClose={onClose}>
      <Async state={st}>
        {(j) => (
          <>
            <dl className="kv-compact" style={{ margin: '0 0 18px' }}>
              {[['Folder', j.folder], ['Reason', j.reasonLabel], ['Started', fmtDateTime(j.createdAt)], ['Finished', j.completedAt ? fmtDateTime(j.completedAt) : '—'],
                ['Re-encrypted by', j.executor ?? (j.status === 'COMPLETED' ? '—' : '—')], ['Activated by', j.committedBy ?? '—'], ['Keys shared with', j.recipients.length ? j.recipients.join(', ') : '—'], ['Attempt', j.generation && j.generation !== '0' ? `#${j.generation}` : '—']]
                .map(([k, v]) => <div className="kv" key={k} style={{ gridTemplateColumns: '150px 1fr' }}><dt>{k}</dt><dd>{v}</dd></div>)}
              <div className="kv" style={{ gridTemplateColumns: '150px 1fr' }}><dt>Progress</dt><dd><Progress done={j.status === 'COMPLETED' ? j.total : j.done} total={j.total} /></dd></div>
              <div className="kv" style={{ gridTemplateColumns: '150px 1fr' }}><dt>Status</dt><dd><StatusBadge status={j.status} /></dd></div>
            </dl>
            <Table rows={j.items} empty="This folder had no documents to re-encrypt. Access keys were updated." columns={[
              { key: 'title', label: 'Document', width: '45%', render: (i) => `${i.title ?? 'Document'} · v${i.versionNumber ?? '?'}` },
              { key: 'status', label: 'Result', width: '30%', render: (i) => <StatusBadge status={i.status} /> },
              { key: 'error', label: 'Note', width: '25%', render: (i) => (i.sample ? 'Sample data (not encrypted)' : i.error ?? '—') },
            ]} />
            <div className="form-actions"><RotationAction job={j} onDone={refresh} size="" /><Button onClick={onClose}>Close</Button></div>
          </>
        )}
      </Async>
    </Modal>
  );
}
