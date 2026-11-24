import { Link } from 'react-router-dom';
import { api } from '../api/endpoints';
import { nEvent } from '../api/normalize';
import { Async, Notice, PageHeader, Table } from '../components/ui';
import { fmtDateTime } from '../utils/format';
import { useAsync } from '../utils/hooks';

// Audit log = hoạt động của CHÍNH BẠN: tài liệu, folder, quyền thành viên.
// Sự kiện khóa / rotation nằm ở Key rotation log, không lặp lại ở đây.
const AUDIT_TYPE = /^(DOCUMENT_|FOLDER_|MEMBER_)/;

export default function AuditLog() {
  const st = useAsync(() => api.listAuditEvents().then((l) => l.map(nEvent).filter((e) => AUDIT_TYPE.test(e.type ?? ''))), []);
  return (
    <>
      <PageHeader title="Audit log" sub="Your own activity: documents, folders and member permissions.">
        <Link className="btn" to="/security/rotation-audit">Key rotation log</Link>
      </PageHeader>
      {st.error?.status === 403 ? <Notice>You don’t have permission to view this log.</Notice> : (
        <Async state={st}>
          {(rows) => <Table rows={rows} empty="No activity recorded yet." columns={[
            { key: 'at', label: 'Date and time', width: '20%', render: (r) => fmtDateTime(r.at) },
            { key: 'label', label: 'Activity', width: '26%' },
            { key: 'item', label: 'Item', width: '30%', render: (r) => (r.item ? r.item : '—') },
            { key: 'detail', label: 'Details', width: '12%' },
            { key: 'folder', label: 'Folder ID', width: '12%' },
          ]} />}
        </Async>
      )}
    </>
  );
}
