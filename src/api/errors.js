export class ApiError extends Error {
  constructor(status, body) {
    const msg = body?.message ?? body?.error?.message ?? (typeof body?.error === 'string' ? body.error : null);
    super(msg || `Request failed (${status})`);
    this.status = status;
    this.code = body?.code ?? body?.error?.code ?? null; // CONTRACT: mã lỗi chưa chốt
    this.body = body;
  }
}
