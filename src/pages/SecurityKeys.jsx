import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/endpoints';
import { nDevice, nRotation } from '../api/normalize';
import { useAuth } from '../auth/AuthContext';
import RotationAction from '../components/RotationAction';
import { Async, Badge, Button, Field, Modal, Notice, PageHeader, Progress, StatusBadge, Table } from '../components/ui';
import { useReauth, useToast } from '../components/Providers';
import { isActiveJob } from '../services/rotation';
import { keyOverview, purgeRetiredKeys, restoreKey, setupKeys } from '../services/vault';
import { KEY_PURPOSE } from '../utils/constants';
import { ellipsisId, fmtDate } from '../utils/format';
import { useAsync } from '../utils/hooks';

const PURPOSE_TEXT = { ENC: 'Access to encrypted document keys', SIGN: 'Verify who uploaded a document' };
const DEVICE_KEY = 'medshare.deviceId';

export default function SecurityKeys() {
  const { user, logout } = useAuth();
  const toast = useToast();
  const reauth = useReauth();
  const [setup, setSetup] = useState(false);
  const [manage, setManage] = useState(null);
  const keys = useAsync(() => keyOverview(user.id), []);
  const jobs = useAsync(async () => {
    const list = (await api.listRotations()).filter(isActiveJob).map(nRotation);
    if (!list.length) await purgeRetiredKeys(user.id).catch(() => {}); // không còn job → xoá private key của khóa đã thu hồi khỏi máy
    return list;
  }, []);
  const devices = useAsync(() => api.listMyDevices().then((l) => l.map(nDevice)), []);

  async function registerDevice() {
    if (!(await reauth())) return;
    try {
      const ua = navigator.userAgent;
      const d = await api.registerDevice({ name: `${/Edg/.test(ua) ? 'Edge' : /Chrome/.test(ua) ? 'Chrome' : /Firefox/.test(ua) ? 'Firefox' : 'Browser'} / ${navigator.platform || 'Unknown OS'}` });
      localStorage.setItem(DEVICE_KEY, d.deviceId ?? d.id);
      toast('Device registered.'); devices.reload();
    } catch (e) { toast(e.message, 'error'); }
  }
  async function revoke(d) {
    if (!window.confirm(`Revoke “${d.name}”? It will be signed out. Private keys already on it can’t be wiped remotely.`)) return;
    if (!(await reauth())) return;
    try { await api.revokeDevice(d.id); toast('Device revoked.'); devices.reload(); } catch (e) { toast(e.message, 'error'); }
  }
  const refresh = () => { keys.reload(); jobs.reload(); };

  return (
    <>
      <PageHeader title="Security & keys" sub="Your encryption identity, signing identity and registered devices.">
        <Button to="/security/rotation-audit">Key rotation log</Button>
      </PageHeader>

      <Async state={keys}>
        {(k) => {
          const replaced = !k.ENC && !k.SIGN && k.history.some((h) => h.status === 'REVOKED');
          return (
            <>
              {!(k.ENC?.status === 'ACTIVE' && k.SIGN?.status === 'ACTIVE') && (
                <Notice tone="warn" action={<Button size="sm" variant="primary" onClick={() => setSetup(true)}>Set up keys</Button>}>
                  {replaced
                    ? <><b>Your previous keys were reported as compromised and can no longer be used.</b> Create new keys. Documents are then re-encrypted with new keys and shared again with you.</>
                    : <>You don’t have both key pairs yet. Keys are created on this device and the private key never leaves it. A recovery backup is created for each key.</>}
                </Notice>
              )}
              <div className="grid2">
                {['ENC', 'SIGN'].map((p) => (
                  <section className="card" key={p} style={{ minHeight: 265 }}>
                    <h2>{KEY_PURPOSE[p]}</h2>
                    <p style={{ margin: '14px 0 18px' }}>{k[p] ? <StatusBadge status={k[p].status} /> : <Badge>Not set up</Badge>}</p>
                    <dl style={{ margin: 0 }}>
                      <div className="kv"><dt>{p === 'ENC' ? 'Public key ID' : 'Signing key ID'}</dt><dd>{ellipsisId(k[p]?.id)}</dd></div>
                      <div className="kv"><dt>{p === 'ENC' ? 'Private key' : 'Private signing key'}</dt><dd>{!k[p] ? '—' : k[p].onDevice ? 'Stored securely on this device' : <span style={{ color: 'var(--danger)' }}>Not on this device — restore from backup</span>}</dd></div>
                      <div className="kv"><dt>Purpose</dt><dd style={{ fontSize: 12 }}>{PURPOSE_TEXT[p]}</dd></div>
                    </dl>
                    <div style={{ marginTop: 14 }}><Button disabled={!k[p]} onClick={() => setManage(k[p])}>Manage backup</Button></div>
                  </section>
                ))}
              </div>
              {k.history.length > 0 && (
                <section className="card" style={{ marginTop: 28 }}>
                  <h2 style={{ marginBottom: 14 }}>Previous keys</h2>
                  <Table rows={k.history} empty="" columns={[
                    { key: 'purpose', label: 'Key type', width: '22%', render: (h) => (h.purpose === 'ENC' ? 'Encryption key' : 'Signing key') },
                    { key: 'id', label: 'Key ID', width: '30%', render: (h) => ellipsisId(h.id) },
                    { key: 'createdAt', label: 'Created', width: '18%', render: (h) => fmtDate(h.createdAt) },
                    { key: 'status', label: 'Status', width: '15%', render: (h) => <StatusBadge status={h.status} /> },
                    { key: 'revokedAt', label: 'Ended', width: '15%', render: (h) => fmtDate(h.revokedAt) },
                  ]} />
                </section>
              )}
            </>
          );
        }}
      </Async>

      <Async state={jobs}>
        {(list) => list.length > 0 && (
          <section className="card" style={{ marginTop: 28 }}>
            <h2 style={{ marginBottom: 6 }}>Document key updates</h2>
            <p className="muted-note" style={{ marginBottom: 14 }}>Document keys are replaced after a compromise or a membership change. Documents stay locked until each update finishes. <Link to="/security/rotation-audit">See full history</Link></p>
            <Table rows={list} columns={[
              { key: 'folder', label: 'Folder', width: '30%' },
              { key: 'reasonLabel', label: 'Reason', width: '26%' },
              { key: 'p', label: 'Progress', width: '18%', render: (j) => <Progress done={j.done} total={j.total} /> },
              { key: 's', label: 'Status', width: '14%', render: (j) => <StatusBadge status={j.status} /> },
              { key: 'a', label: 'Action', width: '12%', stop: true, render: (j) => <RotationAction job={j} onDone={refresh} /> },
            ]} />
          </section>
        )}
      </Async>

      <section className="card" style={{ marginTop: 28 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <h2>Registered devices</h2><Button onClick={registerDevice}>+ Register device</Button>
        </div>
        <Async state={devices}>
          {(rows) => <Table rows={rows} empty="No devices registered." columns={[
            { key: 'name', label: 'Device', width: '40%', render: (d) => (d.id === localStorage.getItem(DEVICE_KEY) ? `This device · ${d.name}` : d.name) },
            { key: 'lastActiveAt', label: 'Last active', width: '25%', render: (d) => fmtDate(d.lastActiveAt) },
            { key: 'status', label: 'Status', width: '15%', render: (d) => <StatusBadge status={d.status} /> },
            { key: 'a', label: 'Action', width: '20%', stop: true, render: (d) => <button className="linkbtn danger" onClick={() => revoke(d)}>Revoke</button> },
          ]} />}
        </Async>
        <p className="muted-note" style={{ marginTop: 14 }}>Both key pairs are distinct: encryption/decryption keys protect access; signing keys attribute uploaded documents.</p>
      </section>

      {setup && <SetupKeys userId={user.id} onClose={() => setSetup(false)} onDone={() => { setSetup(false); refresh(); }} />}
      {manage && <ManageKey k={manage} onClose={() => setManage(null)} onChanged={refresh} logout={logout} />}
    </>
  );
}

function SetupKeys({ userId, onClose, onDone }) {
  const toast = useToast();
  const reauth = useReauth();
  const [pass, setPass] = useState('');
  const [again, setAgain] = useState('');
  const [step, setStep] = useState('');
  const [err, setErr] = useState('');
  async function go(e) {
    e.preventDefault(); setErr('');
    if (!(await reauth())) return;
    try { await setupKeys(userId, pass, setStep); toast('Keys created and activated on this device.'); onDone(); }
    catch (x) { setErr(x.message); setStep(''); }
  }
  return (
    <Modal title="Set up keys" lead="Creates an encryption key and a signing key on this device. The recovery passphrase protects an encrypted backup of each private key. MedShare never receives it, so it can’t be reset." onClose={step ? () => {} : onClose}>
      <form onSubmit={go}>
        <Field label="Recovery passphrase" htmlFor="sp" help="At least 12 characters. Store it somewhere safe."><input id="sp" className="input" type="password" autoComplete="new-password" autoFocus value={pass} onChange={(e) => setPass(e.target.value)} /></Field>
        <Field label="Repeat passphrase" htmlFor="sp2"><input id="sp2" className="input" type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} /></Field>
        {err && <Notice tone="danger">{err}</Notice>}
        {step && <p className="muted-note" role="status"><span className="spinner" /> {step}</p>}
        <div className="form-actions"><Button onClick={onClose} disabled={!!step}>Cancel</Button><Button variant="primary" type="submit" disabled={!!step || pass.length < 12 || pass !== again}>{step ? 'Creating…' : 'Create keys'}</Button></div>
      </form>
    </Modal>
  );
}

function ManageKey({ k, onClose, onChanged, logout }) {
  const { user } = useAuth();
  const toast = useToast();
  const reauth = useReauth();
  const [pass, setPass] = useState('');
  const [busy, setBusy] = useState('');
  const [confirm, setConfirm] = useState(false);
  const run = (name, fn, ok, close = true) => async () => {
    if (!(await reauth())) return;
    setBusy(name);
    try { await fn(); toast(ok); onChanged(); if (close) onClose(); } catch (e) { toast(e.message, 'error'); } finally { setBusy(''); }
  };
  const restore = run('restore', () => restoreKey(user.id, k, pass), 'Key restored on this device.');
  const compromise = run('compromise', async () => { await api.reportKeyCompromise(k.id, { reason: 'USER_REPORTED' }); await logout(); }, 'Key reported. Sign in again to create new keys.', false);
  return (
    <Modal title={`Manage backup · ${KEY_PURPOSE[k.purpose]}`} lead="An encrypted backup of this key was saved when it was created. It can only be opened with your recovery passphrase." onClose={onClose}>
      {k.onDevice
        ? <Notice tone="ok">This key is stored on this device.</Notice>
        : <Notice tone="warn">This key isn’t on this device. Restore it to open documents here.</Notice>}
      <Field label="Recovery passphrase" htmlFor="bp"><input id="bp" className="input" type="password" autoComplete="current-password" value={pass} onChange={(e) => setPass(e.target.value)} /></Field>
      <Button disabled={!pass || !!busy} onClick={restore}>{busy === 'restore' ? 'Restoring…' : 'Restore from backup'}</Button>
      <div className="divider" />
      <h3 style={{ marginBottom: 6 }}>Key exposed?</h3>
      <p className="muted-note" style={{ marginBottom: 12 }}>Reporting stops this key being used, closes related sessions and replaces document keys for every affected folder. You will be signed out and must create new keys. Documents stay locked until the update finishes.</p>
      {confirm
        ? <Button variant="danger solid" disabled={!!busy} onClick={compromise}>{busy === 'compromise' ? 'Reporting…' : 'Yes, report as compromised'}</Button>
        : <Button variant="danger" onClick={() => setConfirm(true)}>Report key compromise</Button>}
      <div className="form-actions" style={{ marginTop: 10 }}><Button onClick={onClose}>Close</Button></div>
    </Modal>
  );
}
