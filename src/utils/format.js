const D = { month: 'short', day: '2-digit', year: 'numeric' };
export const fmtDate = (v) => (v ? new Date(v).toLocaleDateString('en-US', D) : '—');
export const fmtDateTime = (v) => {
  if (!v) return '—';
  const d = new Date(v);
  return `${d.toLocaleDateString('en-US', D)} · ${d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}`;
};
export const fmtSize = (n) => {
  if (n == null) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
};
export const fmtType = (mime, name = '') => {
  const ext = name.split('.').pop().toLowerCase();
  if (mime === 'application/pdf' || ext === 'pdf') return 'PDF document';
  if (mime?.startsWith('image/') || ['png', 'jpg', 'jpeg'].includes(ext)) return `${(mime?.split('/')[1] || ext).toUpperCase()} image`;
  return mime || '—';
};
export const ellipsisId = (id) => (id && id.length > 16 ? `${id.slice(0, 11)}…${id.slice(-4)}` : id || '—');

export function saveBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement('a'), { href: url, download: name });
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
