import { useState } from 'react';
import { api } from '../api/endpoints';
import { useAuth } from '../auth/AuthContext';
import { commitRotationAsOwner, runRotation } from '../services/rotation';
import { Button } from './ui';
import { useReauth, useToast } from './Providers';

/** Nút hành động đúng theo trạng thái job + quyền: tiếp tục re-encrypt / duyệt & kích hoạt / thử lại. */
export default function RotationAction({ job, onDone, size = 'sm' }) {
  const { user } = useAuth();
  const toast = useToast();
  const reauth = useReauth();
  const [busy, setBusy] = useState('');
  const kind = job.canClaim ? 'run' : job.canCommit ? 'commit' : null;
  if (job.status === 'WAITING_FOR_KEY') return <span className="muted" style={{ fontSize: 12 }}>Waiting for {job.waitingFor.join(', ') || 'a member'} to set up new keys</span>;
  const retry = job.status === 'FAILED' && job.canCommit;
  if (!kind && !retry) return null;

  async function go() {
    try {
      if (retry) { if (!(await reauth())) return; await api.retryRotation(job.id, {}); }
      else if (kind === 'run') await runRotation({ rotationId: job.id, userId: user.id, onProgress: setBusy });
      else await commitRotationAsOwner({ rotationId: job.id, userId: user.id, onProgress: setBusy });
      toast(kind === 'commit' ? 'Key update activated.' : 'Key update progressed.');
      onDone?.();
    } catch (e) { toast(e.message, 'error'); } finally { setBusy(''); }
  }
  const label = retry ? 'Retry' : kind === 'run' ? 'Continue re-encryption' : 'Review and activate';
  return <Button size={size} variant="primary" disabled={!!busy} onClick={go}>{busy || label}</Button>;
}
