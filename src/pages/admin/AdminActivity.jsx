import { api } from '../../api/endpoints';
import { nEvent } from '../../api/normalize';
import { Async, PageHeader, Table } from '../../components/ui';
import { fmtDateTime } from '../../utils/format';
import { useAsync } from '../../utils/hooks';

// CONTRACT: chưa có endpoint riêng cho admin activity → dùng listAuditEvents?scope=admin (cần backend xác nhận).
export default function AdminActivity() {
  const st = useAsync(() => api.listAuditEvents({ scope: 'admin' }).then((l) => l.map(nEvent)), []);
  return (
    <>
      <PageHeader title="Admin activity" sub="Review administrative account events." />
      <Async state={st}>
        {(rows) => <Table rows={rows} empty="No administrative events yet." columns={[
          { key: 'at', label: 'Date and time', width: '25%', render: (r) => fmtDateTime(r.at) },
          { key: 'label', label: 'Event', width: '35%' },
          { key: 'staffId', label: 'Staff ID', width: '20%' },
          { key: 'result', label: 'Result', width: '20%' },
        ]} />}
      </Async>
    </>
  );
}
