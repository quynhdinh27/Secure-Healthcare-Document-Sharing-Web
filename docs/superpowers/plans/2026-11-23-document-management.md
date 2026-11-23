# Document Management (backend) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the 10 Document Management endpoints of the API list (section 3) and make the backend run end-to-end locally on MySQL 8 (Docker), local ciphertext storage and dev header auth.

**Architecture:** New `src/documents/` module that follows the folders pattern: an Express router that validates input and maps `{ code }` results to HTTP, a MySQL repository that re-checks membership, role and folder state inside the write transaction (locking `Treatment_Folder` first), and a pure manifest/envelope verifier. Infrastructure units (`config`, `dev-header-auth`, `local-object-storage`, `mysql-key-directory`) are injected through `createApp({...})`. `src/main.js` is the real entry point.

**Tech Stack:** Node.js (tested on v26), Express 5, `mysql2/promise`, `multer` 2 (memory storage), `canonicalize` (JCS), `node:crypto` / WebCrypto, `node --test`, MySQL 8.0 in Docker Compose.

**Spec:** `docs/superpowers/specs/2026-11-23-document-management-design.md`. Deviations from ERD and other docs: `takenote.md`.

## Global Constraints

- Work on branch `feature/document-management`. Commit after every task.
- Do not modify `backend/src/folders/*`, `backend/migrations/001`–`008`, existing tests, or `backend/scripts/smoke-folder-membership.cjs`.
- `backend/src/server.js`: additions only (new destructured options, one `folderPolicyKeys ??= keyDirectory;` line, documents router mounted at `/api/v1` before the folders router).
- IDs for document, version, revision, context: lowercase UUID `CHAR(36) CHARACTER SET ascii COLLATE ascii_bin`. `user_id`: `BIGINT UNSIGNED`, carried in JS as a decimal string. No `ON DELETE CASCADE`.
- Every documents response sets `Cache-Control: no-store`. Errors are `{ code, ...details }` with the status table in spec section 8.
- Signatures: JCS (`canonicalize`) + ECDSA P-256 SHA-256, IEEE-P1363 64 bytes, base64url without padding. Wrapped DEK: exactly 384 bytes. Nonce: 12 bytes. Binary in JSON: base64url without padding.
- `AUTH_MODE=dev` is refused when `NODE_ENV=production`. Dev server listens on `127.0.0.1` only.
- Secrets never in code or git: `.env` and `backend/data/` are gitignored.
- `npm test` must not need MySQL or network. All 16 existing tests keep passing.
- Defaults: `MAX_UPLOAD_MB=25`, `UPLOAD_CONTEXT_TTL_SECONDS=600`, page size 50, search `query` ≤ 100 chars, `documentName` 1–255 chars after trim, `mimeType` ≤ 127 chars.
- Categories: `MEDICAL_REPORT`, `LABORATORY_RESULT`, `PRESCRIPTION`, `MEDICAL_IMAGE`, `OTHER`.

All paths below are relative to `backend/` unless they start with `docs/` or are the repo-root `takenote.md`.

## File map

| File | Responsibility | Task |
|---|---|---|
| `src/config.js` | Read and validate env into a frozen config; `.env` loader | 1 |
| `src/auth/dev-header-auth.js` | `X-Dev-User-Id` → `request.user` | 1 |
| `.env.example`, `.gitignore`, `package.json` | Dev settings, ignore `data/`, deps `mysql2` `multer` | 1 |
| `docker-compose.yml` | MySQL 8.0 for dev | 2 |
| `migrations/000`, `009`–`014` | `User`, `User_Key`, `Document`, `Document_Version`, `Crypto_Revision`, `DEK_Envelope`, `Upload_Context` | 2 |
| `scripts/migrate.cjs` | Apply pending `.sql` files, record in `schema_migrations` | 2 |
| `src/storage/local-object-storage.js` | `put/get/delete` ciphertext under a root dir | 3 |
| `src/keys/mysql-key-directory.js` | Read-only public-key lookups + JWK helpers | 4 |
| `src/documents/document-manifest.js` | Pure verification of manifest, signature, envelopes | 5 |
| `test/helpers/fake-mysql.js`, `test/helpers/document-fixtures.js` | Test doubles and signed-upload fixtures | 5–6 |
| `src/documents/mysql-document-repository.js` | All document SQL and transactions | 6–8 |
| `src/documents/document-router.js` | HTTP layer for the 10 endpoints | 9 |
| `src/server.js` | Mount documents router (additions only) | 9 |
| `src/main.js` | Real entry point: config, pool, auth, storage, listen | 10 |
| `scripts/lib/dev-accounts.cjs`, `scripts/dev-complete-rotations.cjs`, `scripts/seed.cjs` | Dev users/keys, rotation unblock tool, seed | 10 |
| `scripts/lib/dev-document-client.cjs`, `scripts/smoke-documents.cjs`, `README.md` (backend) | Client-side crypto for smoke, end-to-end smoke, docs | 11 |

---

### Task 1: Config, dev header auth, dependencies

**Files:**
- Create: `src/config.js`, `src/auth/dev-header-auth.js`, `.env.example`
- Modify: `.gitignore`, `package.json` (via `npm install`)
- Test: `test/config.test.js`, `test/dev-header-auth.test.js`

**Interfaces:**
- Produces: `loadConfig(env = process.env) → Readonly<{ nodeEnv, port, db: { host, port, user, password, database }, authMode, storage: { driver, dir }, maxUploadBytes, uploadContextTtlSeconds }>`; `loadDotEnv(file?)`; `backendDir`; `devHeaderAuth(request, response, next)`.

- [ ] **Step 1: Install dependencies**

Run: `cd backend && npm install mysql2 multer`
Expected: `package.json` `dependencies` now lists `canonicalize`, `express`, `multer`, `mysql2`.

- [ ] **Step 2: Write the failing tests**

`test/config.test.js`:
```js
const assert = require('node:assert/strict');
const path = require('node:path');
const { test } = require('node:test');
const { backendDir, loadConfig } = require('../src/config');

test('config applies local development defaults', () => {
  const config = loadConfig({ DB_PASSWORD: 'secret' });
  assert.equal(config.nodeEnv, 'development');
  assert.equal(config.port, 3000);
  assert.equal(config.authMode, 'dev');
  assert.deepEqual({ ...config.db }, {
    host: '127.0.0.1', port: 3306, user: 'medshare', password: 'secret', database: 'medshare',
  });
  assert.deepEqual({ ...config.storage }, { driver: 'local', dir: path.join(backendDir, 'data', 'objects') });
  assert.equal(config.maxUploadBytes, 25 * 1024 * 1024);
  assert.equal(config.uploadContextTtlSeconds, 600);
  assert.ok(Object.isFrozen(config) && Object.isFrozen(config.db) && Object.isFrozen(config.storage));
});

test('config rejects unsafe or invalid settings', () => {
  assert.throws(() => loadConfig({}), /DB_PASSWORD is required/);
  assert.throws(() => loadConfig({ DB_PASSWORD: 'x', NODE_ENV: 'production' }), /AUTH_MODE=dev is not allowed/);
  assert.throws(() => loadConfig({ DB_PASSWORD: 'x', AUTH_MODE: 'session' }), /AUTH_MODE must be one of: dev/);
  assert.throws(() => loadConfig({ DB_PASSWORD: 'x', STORAGE_DRIVER: 's3' }), /STORAGE_DRIVER must be one of: local/);
  assert.throws(() => loadConfig({ DB_PASSWORD: 'x', MAX_UPLOAD_MB: '0' }), /MAX_UPLOAD_MB must be an integer/);
  assert.throws(() => loadConfig({ DB_PASSWORD: 'x', PORT: 'abc' }), /PORT must be an integer/);
  assert.throws(() => loadConfig({ DB_PASSWORD: 'x', UPLOAD_CONTEXT_TTL_SECONDS: '5' }), /UPLOAD_CONTEXT_TTL_SECONDS/);
});
```

`test/dev-header-auth.test.js`:
```js
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { devHeaderAuth } = require('../src/auth/dev-header-auth');

function authenticate(value) {
  const request = { get: (name) => (name === 'x-dev-user-id' ? value : undefined) };
  let nextCalls = 0;
  devHeaderAuth(request, {}, () => { nextCalls += 1; });
  assert.equal(nextCalls, 1);
  return request.user;
}

test('dev header auth accepts only a positive decimal user id', () => {
  assert.deepEqual(authenticate('12'), { id: '12' });
  for (const value of [undefined, '', '0', '01', 'abc', '-1', '12 ', '1'.repeat(21)]) {
    assert.equal(authenticate(value), undefined, String(value));
  }
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd backend && node --test test/config.test.js test/dev-header-auth.test.js`
Expected: FAIL with `Cannot find module '../src/config'` and `'../src/auth/dev-header-auth'`.

- [ ] **Step 4: Implement**

`src/config.js`:
```js
const path = require('node:path');

const backendDir = path.resolve(__dirname, '..');

function loadDotEnv(file = path.join(backendDir, '.env')) {
  try {
    process.loadEnvFile(file);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

function readInteger(env, name, fallback, min, max) {
  const raw = env[name] ?? String(fallback);
  if (!/^[0-9]{1,10}$/.test(raw) || Number(raw) < min || Number(raw) > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
  return Number(raw);
}

function loadConfig(env = process.env) {
  const nodeEnv = env.NODE_ENV || 'development';
  const authMode = env.AUTH_MODE || 'dev';
  const storageDriver = env.STORAGE_DRIVER || 'local';
  if (authMode !== 'dev') throw new Error('AUTH_MODE must be one of: dev');
  if (authMode === 'dev' && nodeEnv === 'production') {
    throw new Error('AUTH_MODE=dev is not allowed when NODE_ENV=production');
  }
  if (storageDriver !== 'local') throw new Error('STORAGE_DRIVER must be one of: local');
  if (!env.DB_PASSWORD) throw new Error('DB_PASSWORD is required');
  return Object.freeze({
    nodeEnv,
    port: readInteger(env, 'PORT', 3000, 1, 65535),
    db: Object.freeze({
      host: env.DB_HOST || '127.0.0.1',
      port: readInteger(env, 'DB_PORT', 3306, 1, 65535),
      user: env.DB_USER || 'medshare',
      password: env.DB_PASSWORD,
      database: env.DB_NAME || 'medshare',
    }),
    authMode,
    storage: Object.freeze({
      driver: storageDriver,
      dir: path.resolve(backendDir, env.STORAGE_DIR || 'data/objects'),
    }),
    maxUploadBytes: readInteger(env, 'MAX_UPLOAD_MB', 25, 1, 1024) * 1024 * 1024,
    uploadContextTtlSeconds: readInteger(env, 'UPLOAD_CONTEXT_TTL_SECONDS', 600, 60, 3600),
  });
}

module.exports = { backendDir, loadConfig, loadDotEnv };
```

`src/auth/dev-header-auth.js`:
```js
// Development-only identity: trusts the X-Dev-User-Id header.
// config.js refuses AUTH_MODE=dev in production; replace with the Auth module's
// session middleware, which must set request.user = { id: '<decimal user id>' }.
const USER_ID = /^[1-9][0-9]{0,19}$/;

function devHeaderAuth(request, _response, next) {
  const id = request.get('x-dev-user-id');
  if (typeof id === 'string' && USER_ID.test(id)) request.user = { id };
  next();
}

module.exports = { devHeaderAuth };
```

`.env.example`:
```dotenv
# Copy to backend/.env for local development. Never commit .env.
NODE_ENV=development
PORT=3000

DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=medshare
DB_USER=medshare
DB_PASSWORD=change-me-local-only
# Used only by docker-compose to initialise the MySQL container.
DB_ROOT_PASSWORD=change-me-root-local-only

# dev = trust the X-Dev-User-Id header (refused when NODE_ENV=production).
AUTH_MODE=dev

# local = ciphertext files under STORAGE_DIR (relative to backend/). s3 comes later.
STORAGE_DRIVER=local
STORAGE_DIR=./data/objects

MAX_UPLOAD_MB=25
UPLOAD_CONTEXT_TTL_SECONDS=600
```

`.gitignore` (whole file):
```gitignore
node_modules/
.env
data/
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && npm test`
Expected: PASS, 19 tests (16 existing + 3 new), 0 failures.

- [ ] **Step 6: Commit**

```bash
git add backend/package.json backend/package-lock.json backend/.gitignore backend/.env.example backend/src/config.js backend/src/auth/dev-header-auth.js backend/test/config.test.js backend/test/dev-header-auth.test.js
git commit -m "Add backend config loading and development header auth"
```

---

### Task 2: Docker MySQL, migrations, migration runner

**Files:**
- Create: `docker-compose.yml`, `scripts/migrate.cjs`, `migrations/000_create_user.sql`, `migrations/009_create_user_key.sql`, `migrations/010_create_document.sql`, `migrations/011_create_document_version.sql`, `migrations/012_create_crypto_revision.sql`, `migrations/013_create_dek_envelope.sql`, `migrations/014_create_upload_context.sql`
- Modify: `package.json` (scripts)

**Interfaces:**
- Consumes: `loadConfig`, `loadDotEnv` (Task 1).
- Produces: tables used by Tasks 4, 6–8, 10–11 (columns exactly as below); `npm run migrate`.

- [ ] **Step 1: Write `docker-compose.yml`**

```yaml
# Local MySQL for development. Values come from backend/.env (see .env.example).
services:
  mysql:
    image: mysql:8.0
    container_name: medshare-mysql
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: ${DB_ROOT_PASSWORD:?Set DB_ROOT_PASSWORD in backend/.env}
      MYSQL_DATABASE: ${DB_NAME:-medshare}
      MYSQL_USER: ${DB_USER:-medshare}
      MYSQL_PASSWORD: ${DB_PASSWORD:?Set DB_PASSWORD in backend/.env}
    command:
      - --default-time-zone=+00:00
      - --character-set-server=utf8mb4
      - --collation-server=utf8mb4_0900_ai_ci
    ports:
      - "127.0.0.1:${DB_PORT:-3306}:3306"
    volumes:
      - medshare-mysql:/var/lib/mysql
    healthcheck:
      test: ["CMD-SHELL", "mysqladmin ping -h 127.0.0.1 -uroot -p\"$$MYSQL_ROOT_PASSWORD\" --silent"]
      interval: 5s
      timeout: 5s
      retries: 30
volumes:
  medshare-mysql:
```

- [ ] **Step 2: Write the migrations**

`migrations/000_create_user.sql`:
```sql
-- Minimal account table so Folder_Membership (002) and the document tables can
-- reference users. Owner: Authentication / User Management. Extend it with
-- ALTER TABLE in a new migration (department_id, password_hash, ...); do not
-- recreate it. email/full_name are nullable because smoke-folder-membership.cjs
-- inserts only user_id. See takenote.md section 1.5.
CREATE TABLE `User` (
    user_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    email VARCHAR(255) NULL,
    full_name VARCHAR(255) NULL,
    account_type ENUM('STAFF', 'ADMIN') NOT NULL DEFAULT 'STAFF',
    account_status ENUM('ACTIVE', 'DISABLED') NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id),
    UNIQUE KEY uq_user_email (email)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
```

`migrations/009_create_user_key.sql`:
```sql
-- Minimal public-key registry read by src/keys/mysql-key-directory.js.
-- Owner: Key Management. Extend with ALTER TABLE (proof challenges, backups,
-- retirement timestamps). Status values follow FRS FR-KEY-08 / System design 10.2.
-- See takenote.md section 1.6.
CREATE TABLE User_Key (
    key_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    purpose ENUM('ENCRYPTION', 'SIGNING') NOT NULL,
    algorithm VARCHAR(32) NOT NULL,
    public_key_jwk JSON NOT NULL,
    fingerprint CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    status ENUM('PENDING_VERIFICATION', 'ACTIVE', 'RETIRED', 'COMPROMISED')
        NOT NULL DEFAULT 'PENDING_VERIFICATION',
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    activated_at DATETIME(3) NULL,
    -- NULL for non-active keys, so only one ACTIVE key per user and purpose.
    active_marker TINYINT GENERATED ALWAYS AS (
        CASE WHEN status = 'ACTIVE' THEN 1 END
    ) STORED,
    PRIMARY KEY (key_id),
    UNIQUE KEY uq_user_key_fingerprint (fingerprint),
    UNIQUE KEY uq_user_key_active_purpose (user_id, purpose, active_marker),
    CONSTRAINT fk_user_key_user FOREIGN KEY (user_id) REFERENCES `User` (user_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
```

`migrations/010_create_document.sql`:
```sql
-- current_version_id gets its foreign key in 011 after Document_Version exists.
CREATE TABLE Document (
    document_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    folder_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    document_name VARCHAR(255) NOT NULL,
    category ENUM('MEDICAL_REPORT', 'LABORATORY_RESULT', 'PRESCRIPTION', 'MEDICAL_IMAGE', 'OTHER') NOT NULL,
    original_uploader_id BIGINT UNSIGNED NOT NULL,
    current_version_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (document_id),
    KEY ix_document_folder_updated (folder_id, updated_at),
    KEY ix_document_folder_name (folder_id, document_name),
    CONSTRAINT fk_document_folder FOREIGN KEY (folder_id) REFERENCES Treatment_Folder (folder_id),
    CONSTRAINT fk_document_uploader FOREIGN KEY (original_uploader_id) REFERENCES `User` (user_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
```

`migrations/011_create_document_version.sql`:
```sql
-- Business versions (V1, V2...). Rows are never updated; crypto data lives in Crypto_Revision.
CREATE TABLE Document_Version (
    version_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    document_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    version_number INT UNSIGNED NOT NULL,
    base_version_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    created_by BIGINT UNSIGNED NOT NULL,
    author_key_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    mime_type VARCHAR(127) NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (version_id),
    UNIQUE KEY uq_document_version_number (document_id, version_number),
    CONSTRAINT fk_version_document FOREIGN KEY (document_id) REFERENCES Document (document_id),
    CONSTRAINT fk_version_base FOREIGN KEY (base_version_id) REFERENCES Document_Version (version_id),
    CONSTRAINT fk_version_creator FOREIGN KEY (created_by) REFERENCES `User` (user_id),
    CONSTRAINT fk_version_author_key FOREIGN KEY (author_key_id) REFERENCES User_Key (key_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

ALTER TABLE Document
    ADD CONSTRAINT fk_document_current_version
        FOREIGN KEY (current_version_id) REFERENCES Document_Version (version_id);
```

`migrations/012_create_crypto_revision.sql`:
```sql
-- One encrypted ciphertext per business version per rotation. The 16-byte GCM tag
-- is appended to the ciphertext (WebCrypto output), so there is no tag column.
CREATE TABLE Crypto_Revision (
    revision_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    version_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    revision_number INT UNSIGNED NOT NULL,
    status ENUM('STAGED', 'ACTIVE', 'SUPERSEDED') NOT NULL,
    active_marker TINYINT GENERATED ALWAYS AS (
        CASE WHEN status = 'ACTIVE' THEN 1 END
    ) STORED,
    storage_object_key VARCHAR(80) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    ciphertext_size BIGINT UNSIGNED NOT NULL,
    ciphertext_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    aead_algorithm VARCHAR(16) NOT NULL DEFAULT 'AES-256-GCM',
    nonce VARBINARY(12) NOT NULL,
    policy_version INT UNSIGNED NOT NULL,
    signed_manifest JSON NOT NULL,
    signer_key_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_by BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    activated_at DATETIME(3) NULL,
    PRIMARY KEY (revision_id),
    UNIQUE KEY uq_revision_number (version_id, revision_number),
    UNIQUE KEY uq_revision_active (version_id, active_marker),
    UNIQUE KEY uq_revision_object (storage_object_key),
    CONSTRAINT fk_revision_version FOREIGN KEY (version_id) REFERENCES Document_Version (version_id),
    CONSTRAINT fk_revision_signer_key FOREIGN KEY (signer_key_id) REFERENCES User_Key (key_id),
    CONSTRAINT fk_revision_creator FOREIGN KEY (created_by) REFERENCES `User` (user_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
```

`migrations/013_create_dek_envelope.sql`:
```sql
-- RSA-OAEP-3072 wrapped DEK per crypto revision and recipient (System design 6, 11).
CREATE TABLE DEK_Envelope (
    envelope_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    revision_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    recipient_user_id BIGINT UNSIGNED NOT NULL,
    recipient_membership_id BIGINT UNSIGNED NOT NULL,
    recipient_key_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    wrapped_dek VARBINARY(512) NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (envelope_id),
    UNIQUE KEY uq_envelope_revision_recipient (revision_id, recipient_user_id),
    KEY ix_envelope_recipient (recipient_user_id, revision_id),
    CONSTRAINT fk_envelope_revision FOREIGN KEY (revision_id) REFERENCES Crypto_Revision (revision_id),
    CONSTRAINT fk_envelope_user FOREIGN KEY (recipient_user_id) REFERENCES `User` (user_id),
    CONSTRAINT fk_envelope_membership
        FOREIGN KEY (recipient_membership_id) REFERENCES Folder_Membership (membership_id),
    CONSTRAINT fk_envelope_key FOREIGN KEY (recipient_key_id) REFERENCES User_Key (key_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
```

`migrations/014_create_upload_context.sql`:
```sql
-- One-time upload contexts (API list createUploadContext). document_id has no
-- foreign key because a NEW_DOCUMENT context names a document that does not exist yet.
CREATE TABLE Upload_Context (
    context_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    folder_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    purpose ENUM('NEW_DOCUMENT', 'NEW_VERSION') NOT NULL,
    document_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    version_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    revision_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    base_version_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    version_number INT UNSIGNED NOT NULL,
    policy_version INT UNSIGNED NOT NULL,
    signer_key_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    recipients JSON NOT NULL,
    expires_at DATETIME(3) NOT NULL,
    consumed_at DATETIME(3) NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (context_id),
    KEY ix_upload_context_document (document_id),
    KEY ix_upload_context_folder_expiry (folder_id, expires_at),
    CONSTRAINT fk_upload_context_folder FOREIGN KEY (folder_id) REFERENCES Treatment_Folder (folder_id),
    CONSTRAINT fk_upload_context_user FOREIGN KEY (user_id) REFERENCES `User` (user_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
```

- [ ] **Step 3: Write `scripts/migrate.cjs`**

```js
// Applies migrations/*.sql in filename order and records each in schema_migrations.
// MySQL DDL auto-commits: if a file fails halfway, fix it by hand or reset the
// dev database (docker compose down -v).
const fs = require('node:fs/promises');
const path = require('node:path');
const mysql = require('mysql2/promise');
const { backendDir, loadConfig, loadDotEnv } = require('../src/config');

async function main() {
  loadDotEnv();
  const { db } = loadConfig();
  const connection = await mysql.createConnection({ ...db, multipleStatements: true });
  try {
    await connection.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        filename VARCHAR(255) NOT NULL PRIMARY KEY,
        applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      ) ENGINE = InnoDB
    `);
    const [rows] = await connection.query('SELECT filename FROM schema_migrations');
    const applied = new Set(rows.map((row) => row.filename));
    const dir = path.join(backendDir, 'migrations');
    const files = (await fs.readdir(dir)).filter((file) => /^[0-9]{3}_[a-z0-9_]+\.sql$/.test(file)).sort();
    for (const file of files) {
      if (applied.has(file)) continue;
      console.log(`Applying ${file}`);
      await connection.query(await fs.readFile(path.join(dir, file), 'utf8'));
      await connection.execute('INSERT INTO schema_migrations (filename) VALUES (?)', [file]);
    }
    console.log('Migrations are up to date');
  } finally {
    await connection.end();
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
```

Add to `package.json` `scripts`: `"migrate": "node scripts/migrate.cjs"`.

- [ ] **Step 4: Verify against Docker MySQL**

Run:
```bash
cd backend
[ -f .env ] || cp .env.example .env
docker compose up -d --wait
npm run migrate
npm run migrate
docker compose exec -T mysql sh -c 'mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -e "SHOW TABLES"'
```
Expected: first `migrate` prints `Applying 000_create_user.sql` … `Applying 014_create_upload_context.sql` (15 files) then `Migrations are up to date`; second run prints only `Migrations are up to date`. `SHOW TABLES` lists `Crypto_Revision`, `DEK_Envelope`, `Document`, `Document_Version`, `Folder_Deletion_Operation`, `Folder_Membership`, `Folder_Policy`, `Folder_Policy_Context`, `Folder_Rotation_Job`, `Treatment_Folder`, `Upload_Context`, `User`, `User_Key`, `schema_migrations`.

- [ ] **Step 5: Commit**

```bash
git add backend/docker-compose.yml backend/migrations backend/scripts/migrate.cjs backend/package.json
git commit -m "Add dev MySQL, document schema migrations and migration runner"
```

---

### Task 3: Local object storage

**Files:**
- Create: `src/storage/local-object-storage.js`
- Test: `test/local-object-storage.test.js`

**Interfaces:**
- Produces: `createLocalObjectStorage({ rootDir }) → { put(key, buffer): Promise<void>, get(key): Promise<Buffer>, delete(key): Promise<void> }`. Keys are `<uuid>/<uuid>`; invalid keys reject with `error.code === 'INVALID_OBJECT_KEY'`; `get` of a missing key rejects with `ENOENT`; `delete` of a missing key resolves.

- [ ] **Step 1: Write the failing test**

```js
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { createLocalObjectStorage } = require('../src/storage/local-object-storage');

async function tempStorage(t) {
  const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), 'medshare-objects-'));
  t.after(() => fs.rm(rootDir, { recursive: true, force: true }));
  return { rootDir, storage: createLocalObjectStorage({ rootDir }) };
}

test('local object storage stores, reads and deletes objects under its root', async (t) => {
  const { rootDir, storage } = await tempStorage(t);
  const [prefix, name] = [randomUUID(), randomUUID()];
  const key = `${prefix}/${name}`;
  await storage.put(key, Buffer.from('ciphertext'));
  assert.deepEqual(await storage.get(key), Buffer.from('ciphertext'));
  assert.deepEqual(await fs.readdir(path.join(rootDir, prefix)), [name]);
  await storage.delete(key);
  await assert.rejects(storage.get(key), { code: 'ENOENT' });
  await storage.delete(key);
});

test('local object storage rejects keys outside the object key format', async (t) => {
  const { storage } = await tempStorage(t);
  const id = randomUUID();
  for (const key of ['../x', '/etc/passwd', 'a/b', id, `${id}/../${id}`, `${id.toUpperCase()}/${id}`, `${id}/${id}/x`, 42]) {
    await assert.rejects(storage.put(key, Buffer.from('x')), { code: 'INVALID_OBJECT_KEY' });
    await assert.rejects(storage.get(key), { code: 'INVALID_OBJECT_KEY' });
    await assert.rejects(storage.delete(key), { code: 'INVALID_OBJECT_KEY' });
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && node --test test/local-object-storage.test.js`
Expected: FAIL with `Cannot find module '../src/storage/local-object-storage'`.

- [ ] **Step 3: Implement**

```js
const { randomUUID } = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const OBJECT_KEY = new RegExp(`^${UUID}/${UUID}$`);

// Development storage driver: one file per ciphertext object under rootDir.
// The same put/get/delete interface will be implemented for S3 later.
function createLocalObjectStorage({ rootDir }) {
  const root = path.resolve(rootDir);

  function resolveKey(key) {
    if (typeof key !== 'string' || !OBJECT_KEY.test(key)) {
      throw Object.assign(new Error('Invalid object key'), { code: 'INVALID_OBJECT_KEY' });
    }
    return path.join(root, ...key.split('/'));
  }

  return {
    async put(key, data) {
      const file = resolveKey(key);
      await fs.mkdir(path.dirname(file), { recursive: true });
      const temporary = `${file}.${randomUUID()}.tmp`;
      try {
        await fs.writeFile(temporary, data, { flag: 'wx' });
        await fs.rename(temporary, file);
      } catch (error) {
        await fs.rm(temporary, { force: true });
        throw error;
      }
    },
    async get(key) {
      return fs.readFile(resolveKey(key));
    },
    async delete(key) {
      await fs.rm(resolveKey(key), { force: true });
    },
  };
}

module.exports = { createLocalObjectStorage };
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && npm test`
Expected: PASS, 21 tests.

- [ ] **Step 5: Commit**

```bash
git add backend/src/storage/local-object-storage.js backend/test/local-object-storage.test.js
git commit -m "Add local ciphertext object storage"
```

---

### Task 4: Key directory

**Files:**
- Create: `src/keys/mysql-key-directory.js`
- Test: `test/mysql-key-directory.test.js`

**Interfaces:**
- Produces:
  - `createMysqlKeyDirectory() → { lookupActiveSigningKey(executor, userId): JWK|null, canReceiveFolderKeys(executor, userId): boolean, getActiveSigningKey(executor, userId): Key|null, getActiveEncryptionKey(executor, userId): Key|null, getSigningKeyById(executor, keyId): Key|null }` where `Key = { keyId, userId, purpose, status, publicKeyJwk, fingerprint }` and `executor` is a pool or connection with `execute`.
  - `toPublicJwk(jwk, 'ENCRYPTION'|'SIGNING') → { kty, n, e } | { kty, crv, x, y }` (throws `Invalid public JWK`).
  - `fingerprintPublicJwk(publicJwk) → sha256 hex of JCS(publicJwk)`.
- `lookupActiveSigningKey` / `canReceiveFolderKeys` match the `folderPolicyKeys` contract of `src/folders/folder-policy-signatures.js`.

- [ ] **Step 1: Write the failing test**

```js
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { createMysqlKeyDirectory, fingerprintPublicJwk, toPublicJwk } = require('../src/keys/mysql-key-directory');

test('key directory returns only active keys for the requested purpose', async () => {
  const jwk = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' };
  const connection = {
    async execute(sql, args) {
      if (sql.includes('FROM `User`')) {
        assert.match(sql, /u\.account_status = 'ACTIVE'/);
        assert.match(sql, /k\.purpose = 'ENCRYPTION' AND k\.status = 'ACTIVE'/);
        return [args[0] === '7' ? [{ eligible: 1 }] : []];
      }
      if (sql.includes('k.key_id = ?')) {
        return [[{ keyId: args[0], userId: '7', purpose: 'SIGNING', status: 'RETIRED', publicKeyJwk: JSON.stringify(jwk), fingerprint: 'f' }]];
      }
      assert.match(sql, /k\.user_id = \? AND k\.purpose = \? AND k\.status = 'ACTIVE'/);
      return [args[0] === '7'
        ? [{ keyId: 'key-' + args[1], userId: '7', purpose: args[1], status: 'ACTIVE', publicKeyJwk: jwk, fingerprint: 'f' }]
        : []];
    },
  };
  const keys = createMysqlKeyDirectory();
  assert.deepEqual(await keys.lookupActiveSigningKey(connection, '7'), jwk);
  assert.equal(await keys.lookupActiveSigningKey(connection, '8'), null);
  assert.equal((await keys.getActiveSigningKey(connection, '7')).keyId, 'key-SIGNING');
  assert.equal((await keys.getActiveEncryptionKey(connection, '7')).keyId, 'key-ENCRYPTION');
  assert.equal(await keys.getActiveEncryptionKey(connection, '8'), null);
  assert.equal(await keys.canReceiveFolderKeys(connection, '7'), true);
  assert.equal(await keys.canReceiveFolderKeys(connection, '8'), false);
  const retired = await keys.getSigningKeyById(connection, 'k1');
  assert.deepEqual(retired.publicKeyJwk, jwk);
  assert.equal(retired.status, 'RETIRED');
});

test('public JWKs keep only required members and have a canonical fingerprint', () => {
  const ec = { kty: 'EC', crv: 'P-256', x: 'abc', y: 'def', ext: true, key_ops: ['verify'] };
  assert.deepEqual(toPublicJwk(ec, 'SIGNING'), { kty: 'EC', crv: 'P-256', x: 'abc', y: 'def' });
  assert.deepEqual(toPublicJwk({ kty: 'RSA', n: 'n', e: 'AQAB', alg: 'RSA-OAEP-256' }, 'ENCRYPTION'), { kty: 'RSA', n: 'n', e: 'AQAB' });
  assert.equal(
    fingerprintPublicJwk({ y: 'def', x: 'abc', crv: 'P-256', kty: 'EC' }),
    fingerprintPublicJwk(toPublicJwk(ec, 'SIGNING')),
  );
  assert.match(fingerprintPublicJwk(toPublicJwk(ec, 'SIGNING')), /^[0-9a-f]{64}$/);
  assert.throws(() => toPublicJwk({ ...ec, d: 'secret' }, 'SIGNING'), /Invalid public JWK/);
  assert.throws(() => toPublicJwk(ec, 'ENCRYPTION'), /Invalid public JWK/);
  assert.throws(() => toPublicJwk({ kty: 'EC', crv: 'P-384', x: 'a', y: 'b' }, 'SIGNING'), /Invalid public JWK/);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && node --test test/mysql-key-directory.test.js`
Expected: FAIL with `Cannot find module '../src/keys/mysql-key-directory'`.

- [ ] **Step 3: Implement**

```js
const { createHash } = require('node:crypto');
const canonicalize = require('canonicalize');

// Read-only public-key lookups over User_Key. Key registration, proof of
// possession and backups belong to the Key Management module.
const publicMembers = {
  ENCRYPTION: { fixed: { kty: 'RSA' }, members: ['kty', 'n', 'e'] },
  SIGNING: { fixed: { kty: 'EC', crv: 'P-256' }, members: ['kty', 'crv', 'x', 'y'] },
};

function toPublicJwk(jwk, purpose) {
  const profile = publicMembers[purpose];
  if (!profile) throw new Error('Unknown key purpose');
  const valid = jwk && typeof jwk === 'object' && jwk.d === undefined
    && Object.entries(profile.fixed).every(([name, value]) => jwk[name] === value)
    && profile.members.every((name) => typeof jwk[name] === 'string' && jwk[name] !== '');
  if (!valid) throw new Error('Invalid public JWK');
  return Object.fromEntries(profile.members.map((name) => [name, jwk[name]]));
}

function fingerprintPublicJwk(publicJwk) {
  return createHash('sha256').update(canonicalize(publicJwk)).digest('hex');
}

const keyColumns = `
  k.key_id AS keyId, CAST(k.user_id AS CHAR) AS userId, k.purpose, k.status,
  k.public_key_jwk AS publicKeyJwk, k.fingerprint
`;

function toKey(row) {
  if (!row) return null;
  const publicKeyJwk = typeof row.publicKeyJwk === 'string' ? JSON.parse(row.publicKeyJwk) : row.publicKeyJwk;
  return { ...row, publicKeyJwk };
}

function createMysqlKeyDirectory() {
  async function findActiveKey(executor, userId, purpose) {
    const [[row]] = await executor.execute(`
      SELECT ${keyColumns} FROM User_Key AS k
      WHERE k.user_id = ? AND k.purpose = ? AND k.status = 'ACTIVE'
    `, [userId, purpose]);
    return toKey(row);
  }
  return {
    async lookupActiveSigningKey(executor, userId) {
      return (await findActiveKey(executor, userId, 'SIGNING'))?.publicKeyJwk ?? null;
    },
    async canReceiveFolderKeys(executor, userId) {
      const [[row]] = await executor.execute(`
        SELECT 1 AS eligible FROM \`User\` AS u
        INNER JOIN User_Key AS k
          ON k.user_id = u.user_id AND k.purpose = 'ENCRYPTION' AND k.status = 'ACTIVE'
        WHERE u.user_id = ? AND u.account_status = 'ACTIVE'
      `, [userId]);
      return Boolean(row);
    },
    getActiveSigningKey(executor, userId) {
      return findActiveKey(executor, userId, 'SIGNING');
    },
    getActiveEncryptionKey(executor, userId) {
      return findActiveKey(executor, userId, 'ENCRYPTION');
    },
    async getSigningKeyById(executor, keyId) {
      const [[row]] = await executor.execute(`
        SELECT ${keyColumns} FROM User_Key AS k WHERE k.key_id = ? AND k.purpose = 'SIGNING'
      `, [keyId]);
      return toKey(row);
    },
  };
}

module.exports = { createMysqlKeyDirectory, fingerprintPublicJwk, toPublicJwk };
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && npm test`
Expected: PASS, 23 tests.

- [ ] **Step 5: Commit**

```bash
git add backend/src/keys/mysql-key-directory.js backend/test/mysql-key-directory.test.js
git commit -m "Add read-only MySQL public key directory"
```

---
### Task 5: Manifest and envelope verification

**Files:**
- Create: `src/documents/document-manifest.js`, `test/helpers/document-fixtures.js`
- Test: `test/document-manifest.test.js`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `verifyDocumentUpload({ context, manifest, signature, envelopes, signerPublicJwk, ciphertext: { sha256, size } }) → { nonce: Buffer, envelopes: [{ userId, membershipId, keyId, wrappedDek: Buffer }] } | { code }`, codes in check order: `MANIFEST_MISMATCH`, `CIPHERTEXT_HASH_MISMATCH`, `INVALID_SIGNATURE`, `RECIPIENTS_MISMATCH`.
  - `context` shape (also the repository's context row after parsing): `{ contextId, purpose, folderId, userId, documentId, versionId, revisionId, versionNumber, baseVersionId, policyVersion, signerKeyId, recipients: [{ userId, membershipId, keyId, fingerprint }] }` (recipients sorted by numeric `userId`).
  - `MANIFEST_PURPOSE = 'DOCUMENT_VERSION_UPLOAD'`, `WRAPPED_DEK_BYTES = 384`.
  - Test helpers: `createSigner() → { publicKeyJwk, sign(payload) }`, `createUploadContextFixture(overrides)`, `createSignedUpload(context, signer, ciphertext?) → { ciphertext, manifest, envelopes, signature }`, `sha256Hex(data)`.

- [ ] **Step 1: Write the test helpers**

`test/helpers/document-fixtures.js`:
```js
// Shared fixtures for document tests: a browser-style ECDSA signer and a
// signed upload that matches an issued upload context.
const { createHash, randomBytes, randomUUID, webcrypto } = require('node:crypto');
const canonicalize = require('canonicalize');

const { subtle } = webcrypto;

function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

async function createSigner() {
  const { publicKey, privateKey } = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const { kty, crv, x, y } = await subtle.exportKey('jwk', publicKey);
  return {
    publicKeyJwk: { kty, crv, x, y },
    async sign(payload) {
      const signature = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, Buffer.from(canonicalize(payload)));
      return Buffer.from(signature).toString('base64url');
    },
  };
}

function createUploadContextFixture(overrides = {}) {
  return {
    contextId: randomUUID(),
    purpose: 'NEW_DOCUMENT',
    folderId: randomUUID(),
    userId: '7',
    documentId: randomUUID(),
    versionId: randomUUID(),
    revisionId: randomUUID(),
    versionNumber: 1,
    baseVersionId: null,
    policyVersion: 3,
    signerKeyId: randomUUID(),
    recipients: [
      { userId: '7', membershipId: '70', keyId: randomUUID(), fingerprint: 'a'.repeat(64) },
      { userId: '9', membershipId: '90', keyId: randomUUID(), fingerprint: 'b'.repeat(64) },
    ],
    ...overrides,
  };
}

async function createSignedUpload(context, signer, ciphertext = randomBytes(64)) {
  const envelopes = context.recipients.map(({ userId, keyId }) => ({
    userId, keyId, wrappedDek: randomBytes(384).toString('base64url'),
  }));
  const manifest = {
    purpose: 'DOCUMENT_VERSION_UPLOAD',
    contextId: context.contextId,
    folderId: context.folderId,
    documentId: context.documentId,
    versionId: context.versionId,
    revisionId: context.revisionId,
    versionNumber: context.versionNumber,
    baseVersionId: context.baseVersionId,
    policyVersion: context.policyVersion,
    actorUserId: context.userId,
    signerKeyId: context.signerKeyId,
    aead: { alg: 'AES-256-GCM', nonce: randomBytes(12).toString('base64url') },
    ciphertextSha256: sha256Hex(ciphertext),
    ciphertextSize: ciphertext.length,
    authorRecordSha256: sha256Hex('author-record'),
    recipients: envelopes.map(({ userId, keyId, wrappedDek }) => ({
      userId, keyId, wrappedDekSha256: sha256Hex(Buffer.from(wrappedDek, 'base64url')),
    })),
  };
  return { ciphertext, manifest, envelopes, signature: await signer.sign(manifest) };
}

module.exports = { createSignedUpload, createSigner, createUploadContextFixture, sha256Hex };
```

- [ ] **Step 2: Write the failing test**

`test/document-manifest.test.js`:
```js
const assert = require('node:assert/strict');
const { randomBytes, randomUUID } = require('node:crypto');
const { test } = require('node:test');
const { verifyDocumentUpload } = require('../src/documents/document-manifest');
const { createSignedUpload, createSigner, createUploadContextFixture, sha256Hex } = require('./helpers/document-fixtures');

async function validUpload() {
  const signer = await createSigner();
  const context = createUploadContextFixture();
  const upload = await createSignedUpload(context, signer);
  const input = {
    context,
    manifest: upload.manifest,
    signature: upload.signature,
    envelopes: upload.envelopes,
    signerPublicJwk: signer.publicKeyJwk,
    ciphertext: { sha256: sha256Hex(upload.ciphertext), size: upload.ciphertext.length },
  };
  return { context, input };
}

test('upload evidence that matches the issued context is accepted', async () => {
  const { context, input } = await validUpload();
  const result = verifyDocumentUpload(input);
  assert.equal(result.code, undefined);
  assert.equal(result.nonce.length, 12);
  assert.deepEqual(
    result.envelopes.map(({ userId, membershipId, keyId, wrappedDek }) => [userId, membershipId, keyId, wrappedDek.length]),
    context.recipients.map(({ userId, membershipId, keyId }) => [userId, membershipId, keyId, 384]),
  );
  const reordered = verifyDocumentUpload({ ...input, envelopes: [...input.envelopes].reverse() });
  assert.equal(reordered.code, undefined);
});

test('manifest fields bound to the context or profile cannot change', async () => {
  const { input } = await validUpload();
  const { manifest } = input;
  const bound = {
    purpose: 'OTHER', contextId: randomUUID(), folderId: randomUUID(), documentId: randomUUID(),
    versionId: randomUUID(), revisionId: randomUUID(), versionNumber: 2, baseVersionId: randomUUID(),
    policyVersion: 4, actorUserId: '9', signerKeyId: randomUUID(),
  };
  for (const [field, value] of Object.entries(bound)) {
    assert.equal(verifyDocumentUpload({ ...input, manifest: { ...manifest, [field]: value } }).code, 'MANIFEST_MISMATCH', field);
  }
  const { authorRecordSha256, ...missingField } = manifest;
  assert.ok(authorRecordSha256);
  const variants = [
    missingField,
    { ...manifest, extra: true },
    { ...manifest, aead: { alg: 'AES-128-GCM', nonce: manifest.aead.nonce } },
    { ...manifest, aead: { alg: 'AES-256-GCM', nonce: randomBytes(11).toString('base64url') } },
    { ...manifest, aead: { ...manifest.aead, nonce: manifest.aead.nonce + '=' } },
    { ...manifest, ciphertextSha256: 'A'.repeat(64) },
    { ...manifest, authorRecordSha256: 42 },
    { ...manifest, ciphertextSize: 15 },
    { ...manifest, recipients: [...manifest.recipients].reverse() },
    { ...manifest, recipients: manifest.recipients.slice(1) },
    { ...manifest, recipients: [manifest.recipients[0], { ...manifest.recipients[1], keyId: randomUUID() }] },
  ];
  for (const variant of variants) {
    assert.equal(verifyDocumentUpload({ ...input, manifest: variant }).code, 'MANIFEST_MISMATCH');
  }
  assert.equal(verifyDocumentUpload({ ...input, ciphertext: { ...input.ciphertext, size: input.ciphertext.size + 1 } }).code, 'CIPHERTEXT_HASH_MISMATCH');
  assert.equal(verifyDocumentUpload({ ...input, ciphertext: { ...input.ciphertext, sha256: sha256Hex('other') } }).code, 'CIPHERTEXT_HASH_MISMATCH');
});

test('the signature must come from the signer key over the exact manifest', async () => {
  const { input } = await validUpload();
  const other = await createSigner();
  assert.equal(verifyDocumentUpload({ ...input, signerPublicJwk: other.publicKeyJwk }).code, 'INVALID_SIGNATURE');
  assert.equal(verifyDocumentUpload({ ...input, signerPublicJwk: { ...input.signerPublicJwk, d: 'secret' } }).code, 'INVALID_SIGNATURE');
  const changed = { ...input.manifest, authorRecordSha256: sha256Hex('other') };
  assert.equal(verifyDocumentUpload({ ...input, manifest: changed }).code, 'INVALID_SIGNATURE');
  const standardBase64 = Buffer.from(input.signature, 'base64url').toString('base64');
  for (const signature of [input.signature + 'A', input.signature.slice(1), standardBase64, 42]) {
    assert.equal(verifyDocumentUpload({ ...input, signature }).code, 'INVALID_SIGNATURE');
  }
});

test('every current recipient gets exactly one well-formed envelope', async () => {
  const { input } = await validUpload();
  const [first, second] = input.envelopes;
  const variants = [
    [first],
    [first, second, { ...second, userId: '11' }],
    [first, { ...first }],
    [first, { ...second, keyId: randomUUID() }],
    [first, { ...second, wrappedDek: randomBytes(384).toString('base64url') }],
    [first, { ...second, wrappedDek: randomBytes(383).toString('base64url') }],
    [first, { ...second, wrappedDek: randomBytes(385).toString('base64url') }],
    [first, { ...second, extra: 1 }],
    'not-an-array',
  ];
  for (const envelopes of variants) {
    assert.equal(verifyDocumentUpload({ ...input, envelopes }).code, 'RECIPIENTS_MISMATCH');
  }
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd backend && node --test test/document-manifest.test.js`
Expected: FAIL with `Cannot find module '../src/documents/document-manifest'`.

- [ ] **Step 4: Implement**

`src/documents/document-manifest.js`:
```js
const { createHash, createPublicKey, verify } = require('node:crypto');
const canonicalize = require('canonicalize');

// Pure checks of the signed CryptoManifest and DEK envelopes against an issued
// upload context (spec section 7.3-7.4). No database access.
const MANIFEST_PURPOSE = 'DOCUMENT_VERSION_UPLOAD';
const WRAPPED_DEK_BYTES = 384;
const NONCE_BYTES = 12;
const GCM_TAG_BYTES = 16;
const manifestKeys = [
  'purpose', 'contextId', 'folderId', 'documentId', 'versionId', 'revisionId', 'versionNumber',
  'baseVersionId', 'policyVersion', 'actorUserId', 'signerKeyId', 'aead', 'ciphertextSha256',
  'ciphertextSize', 'authorRecordSha256', 'recipients',
];

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value, keys) {
  return isPlainObject(value) && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function isSha256Hex(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function decodeBase64url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.toString('base64url') === value ? bytes : null;
}

function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

function contextBoundFields(context) {
  return {
    purpose: MANIFEST_PURPOSE,
    contextId: context.contextId,
    folderId: context.folderId,
    documentId: context.documentId,
    versionId: context.versionId,
    revisionId: context.revisionId,
    versionNumber: Number(context.versionNumber),
    baseVersionId: context.baseVersionId ?? null,
    policyVersion: Number(context.policyVersion),
    actorUserId: context.userId,
    signerKeyId: context.signerKeyId,
  };
}

function checkManifest(context, manifest) {
  const mismatch = { code: 'MANIFEST_MISMATCH' };
  if (!hasExactKeys(manifest, manifestKeys)) return mismatch;
  const bound = contextBoundFields(context);
  if (Object.entries(bound).some(([key, value]) => manifest[key] !== value)) return mismatch;
  if (!hasExactKeys(manifest.aead, ['alg', 'nonce']) || manifest.aead.alg !== 'AES-256-GCM') return mismatch;
  const nonce = decodeBase64url(manifest.aead.nonce);
  if (!nonce || nonce.length !== NONCE_BYTES) return mismatch;
  if (!isSha256Hex(manifest.ciphertextSha256) || !isSha256Hex(manifest.authorRecordSha256)) return mismatch;
  if (!Number.isSafeInteger(manifest.ciphertextSize) || manifest.ciphertextSize < GCM_TAG_BYTES) return mismatch;
  const { recipients } = context;
  if (!Array.isArray(manifest.recipients) || manifest.recipients.length !== recipients.length) return mismatch;
  const recipientsMatch = manifest.recipients.every((entry, index) => (
    hasExactKeys(entry, ['userId', 'keyId', 'wrappedDekSha256'])
    && entry.userId === recipients[index].userId
    && entry.keyId === recipients[index].keyId
    && isSha256Hex(entry.wrappedDekSha256)
  ));
  return recipientsMatch ? { nonce } : mismatch;
}

// Same profile as src/folders/folder-policy-signatures.js (not exported there).
function verifyManifestSignature(publicJwk, manifest, signature) {
  if (publicJwk?.kty !== 'EC' || publicJwk.crv !== 'P-256' || publicJwk.d !== undefined
      || typeof signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(signature)) {
    return false;
  }
  const bytes = Buffer.from(signature, 'base64url');
  if (bytes.length !== 64 || bytes.toString('base64url') !== signature) return false;
  try {
    const key = createPublicKey({ key: publicJwk, format: 'jwk' });
    return verify('sha256', Buffer.from(canonicalize(manifest), 'utf8'), { key, dsaEncoding: 'ieee-p1363' }, bytes);
  } catch {
    return false;
  }
}

function checkEnvelopes(context, manifest, envelopes) {
  const mismatch = { code: 'RECIPIENTS_MISMATCH' };
  if (!Array.isArray(envelopes) || envelopes.length !== context.recipients.length) return mismatch;
  const byUser = new Map();
  for (const envelope of envelopes) {
    if (!hasExactKeys(envelope, ['userId', 'keyId', 'wrappedDek']) || typeof envelope.userId !== 'string'
        || byUser.has(envelope.userId)) {
      return mismatch;
    }
    byUser.set(envelope.userId, envelope);
  }
  const accepted = [];
  for (const [index, recipient] of context.recipients.entries()) {
    const envelope = byUser.get(recipient.userId);
    const wrappedDek = decodeBase64url(envelope?.wrappedDek);
    if (!envelope || envelope.keyId !== recipient.keyId || !wrappedDek
        || wrappedDek.length !== WRAPPED_DEK_BYTES
        || sha256Hex(wrappedDek) !== manifest.recipients[index].wrappedDekSha256) {
      return mismatch;
    }
    accepted.push({ userId: recipient.userId, membershipId: recipient.membershipId, keyId: recipient.keyId, wrappedDek });
  }
  return { envelopes: accepted };
}

function verifyDocumentUpload({ context, manifest, signature, envelopes, signerPublicJwk, ciphertext }) {
  const checked = checkManifest(context, manifest);
  if (checked.code) return checked;
  if (manifest.ciphertextSha256 !== ciphertext?.sha256 || manifest.ciphertextSize !== ciphertext?.size) {
    return { code: 'CIPHERTEXT_HASH_MISMATCH' };
  }
  if (!verifyManifestSignature(signerPublicJwk, manifest, signature)) return { code: 'INVALID_SIGNATURE' };
  const accepted = checkEnvelopes(context, manifest, envelopes);
  if (accepted.code) return accepted;
  return { nonce: checked.nonce, envelopes: accepted.envelopes };
}

module.exports = { MANIFEST_PURPOSE, WRAPPED_DEK_BYTES, verifyDocumentUpload };
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && npm test`
Expected: PASS, 27 tests.

- [ ] **Step 6: Commit**

```bash
git add backend/src/documents/document-manifest.js backend/test/document-manifest.test.js backend/test/helpers/document-fixtures.js
git commit -m "Verify document manifests, signatures and DEK envelopes"
```

---
### Task 6: Document repository: reads and folder readiness

**Files:**
- Create: `src/documents/mysql-document-repository.js`, `test/helpers/fake-mysql.js`
- Test: `test/mysql-document-repository.test.js`

**Interfaces:**
- Consumes: `hasFolderPermission(membership, action)` from `src/folders/folder-router.js` (read only); key directory `getSigningKeyById` (Task 4).
- Produces `createMysqlDocumentRepository(pool, { keyDirectory, uploadContextTtlSeconds = 600 })` with:
  - `listDocumentsForUser(userId, folderId, { query, category, page }) → { documents, nextPage } | { code: 'FORBIDDEN' }`
  - `findDocumentForUser(userId, documentId) → Document & { role } | null`
  - `listVersionsForUser(userId, documentId) → { versions } | null`
  - `getVersionManifestForUser(userId, versionId) → { versionId, documentId, folderId, revisionId, manifest, signature, signer: { userId, keyId, publicKeyJwk }, envelope: { keyId, wrappedDek } } | { code }`
  - `getVersionContentForUser(userId, versionId, revisionId?) → { revisionId, objectKey, ciphertextSize } | { code }`
  - `Document = { documentId, folderId, documentName, category, originalUploaderId, currentVersionId, currentVersionNumber, ciphertextSize, createdAt, updatedAt }`
- Test helper: `createFakeMysql(handler) → { pool, connection, events }`. `handler(sql, args, events)` receives SQL with whitespace collapsed to single spaces and trimmed.

- [ ] **Step 1: Write the fake MySQL helper**

`test/helpers/fake-mysql.js`:
```js
// Minimal mysql2/promise double. SQL reaches the handler with whitespace collapsed,
// so tests can match on stable fragments. Transaction calls are recorded in events.
function createFakeMysql(handler) {
  const events = [];
  const run = async (sql, args = []) => handler(sql.replace(/\s+/g, ' ').trim(), args, events);
  const connection = {
    execute: run,
    query: run,
    async beginTransaction() { events.push('begin'); },
    async commit() { events.push('commit'); },
    async rollback() { events.push('rollback'); },
    release() { events.push('release'); },
  };
  const pool = { execute: run, query: run, async getConnection() { return connection; } };
  return { connection, events, pool };
}

module.exports = { createFakeMysql };
```

- [ ] **Step 2: Write the failing tests**

`test/mysql-document-repository.test.js`:
```js
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { createMysqlDocumentRepository } = require('../src/documents/mysql-document-repository');
const { createFakeMysql } = require('./helpers/fake-mysql');

const folderId = '11111111-1111-4111-8111-111111111111';
const documentId = '22222222-2222-4222-8222-222222222222';
const versionId = '33333333-3333-4333-8333-333333333333';
const revisionId = '44444444-4444-4444-8444-444444444444';

test('document lists require active membership and escape search filters', async () => {
  const { pool } = createFakeMysql((sql, args) => {
    if (sql.includes('FROM Folder_Membership WHERE folder_id = ? AND user_id = ?')) {
      return [args[1] === '7' ? [{ role: 'VIEWER', status: 'ACTIVE' }] : []];
    }
    assert.match(sql, /d\.document_name LIKE \? ESCAPE '!'/);
    assert.match(sql, /d\.category = \?/);
    assert.match(sql, /ORDER BY d\.updated_at DESC, d\.document_id LIMIT \? OFFSET \?$/);
    assert.deepEqual(args, [folderId, '%50!%!_x!!%', 'LABORATORY_RESULT', 51, 50]);
    return [Array.from({ length: 51 }, (_, index) => ({ documentId: String(index), currentVersionNumber: 1, ciphertextSize: '64' }))];
  });
  const repository = createMysqlDocumentRepository(pool, { keyDirectory: {} });
  assert.deepEqual(await repository.listDocumentsForUser('8', folderId, { query: '', page: 1 }), { code: 'FORBIDDEN' });
  const result = await repository.listDocumentsForUser('7', folderId, { query: '50%_x!', category: 'LABORATORY_RESULT', page: 2 });
  assert.equal(result.documents.length, 50);
  assert.equal(result.documents[0].ciphertextSize, 64);
  assert.equal(result.nextPage, 3);
});

test('version history lists retained business versions and marks the current one', async () => {
  const { pool } = createFakeMysql((sql, args) => {
    if (sql.startsWith('SELECT d.current_version_id AS currentVersionId')) {
      return [args[0] === '7' ? [{ currentVersionId: 'v2' }] : []];
    }
    assert.match(sql, /ORDER BY v\.version_number DESC$/);
    assert.deepEqual(args, [documentId]);
    return [[{ versionId: 'v2', versionNumber: 2, ciphertextSize: '80' }, { versionId: 'v1', versionNumber: 1, ciphertextSize: '64' }]];
  });
  const repository = createMysqlDocumentRepository(pool, { keyDirectory: {} });
  assert.equal(await repository.listVersionsForUser('8', documentId), null);
  assert.deepEqual(await repository.listVersionsForUser('7', documentId), {
    versions: [
      { versionId: 'v2', versionNumber: 2, ciphertextSize: 80, isCurrent: true },
      { versionId: 'v1', versionNumber: 1, ciphertextSize: 64, isCurrent: false },
    ],
  });
});

test('version downloads need a ready folder and return only the caller envelope', async () => {
  const state = { rotationStatus: null, deleting: 0, envelope: true };
  const { pool } = createFakeMysql((sql, args) => {
    if (sql.includes('FROM Document_Version AS v INNER JOIN Document AS d')) {
      return [args[0] === '7' && args[1] === versionId ? [{ versionId, documentId, folderId, role: 'VIEWER', status: 'ACTIVE' }] : []];
    }
    if (sql.includes('FROM Folder_Policy')) {
      return [[{ policyVersion: 3, rotationStatus: state.rotationStatus, deleting: state.deleting }]];
    }
    if (sql.includes("FROM Crypto_Revision AS r WHERE r.version_id = ? AND r.status = 'ACTIVE'")) {
      return [[{
        revisionId, objectKey: `${revisionId}/obj`, ciphertextSize: '3', signerKeyId: 'signer-key',
        signedManifest: { manifest: { versionId }, signature: 'sig' },
      }]];
    }
    assert.match(sql, /FROM DEK_Envelope WHERE revision_id = \? AND recipient_user_id = \?$/);
    assert.deepEqual(args, [revisionId, '7']);
    return [state.envelope ? [{ keyId: 'enc-key', wrappedDek: Buffer.from([1, 2, 3]) }] : []];
  });
  const keyDirectory = {
    async getSigningKeyById(executor, keyId) {
      assert.equal(executor, pool);
      return { userId: '5', keyId, publicKeyJwk: { kty: 'EC' } };
    },
  };
  const repository = createMysqlDocumentRepository(pool, { keyDirectory });
  assert.deepEqual(await repository.getVersionManifestForUser('7', versionId), {
    versionId, documentId, folderId, revisionId,
    manifest: { versionId }, signature: 'sig',
    signer: { userId: '5', keyId: 'signer-key', publicKeyJwk: { kty: 'EC' } },
    envelope: { keyId: 'enc-key', wrappedDek: 'AQID' },
  });
  assert.deepEqual(await repository.getVersionContentForUser('7', versionId, revisionId), {
    revisionId, objectKey: `${revisionId}/obj`, ciphertextSize: 3,
  });
  assert.deepEqual(await repository.getVersionContentForUser('7', versionId, folderId), { code: 'REVISION_CHANGED', revisionId });
  assert.deepEqual(await repository.getVersionManifestForUser('8', versionId), { code: 'VERSION_NOT_FOUND' });
  state.envelope = false;
  assert.deepEqual(await repository.getVersionManifestForUser('7', versionId), { code: 'ENVELOPE_NOT_AVAILABLE' });
  for (const [rotationStatus, deleting] of [['PENDING', 0], ['WAITING_FOR_OWNER', 0], [null, 1]]) {
    Object.assign(state, { rotationStatus, deleting });
    assert.deepEqual(await repository.getVersionContentForUser('7', versionId), { code: 'FOLDER_NOT_READY' });
  }
  Object.assign(state, { rotationStatus: 'COMPLETED', deleting: 0 });
  assert.equal((await repository.getVersionContentForUser('7', versionId)).revisionId, revisionId);
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd backend && node --test test/mysql-document-repository.test.js`
Expected: FAIL with `Cannot find module '../src/documents/mysql-document-repository'`.

- [ ] **Step 4: Implement the repository skeleton and reads**

`src/documents/mysql-document-repository.js`:
```js
const { randomUUID } = require('node:crypto');
const { hasFolderPermission } = require('../folders/folder-router');
const { verifyDocumentUpload } = require('./document-manifest');

const PAGE_SIZE = 50;

const documentColumns = `
  d.document_id AS documentId, d.folder_id AS folderId, d.document_name AS documentName,
  d.category, CAST(d.original_uploader_id AS CHAR) AS originalUploaderId,
  d.current_version_id AS currentVersionId, v.version_number AS currentVersionNumber,
  r.ciphertext_size AS ciphertextSize, d.created_at AS createdAt, d.updated_at AS updatedAt
`;
const currentRevisionJoins = `
  LEFT JOIN Document_Version AS v ON v.version_id = d.current_version_id
  LEFT JOIN Crypto_Revision AS r ON r.version_id = v.version_id AND r.status = 'ACTIVE'
`;
const callerMembershipJoin = `
  INNER JOIN Folder_Membership AS m
    ON m.folder_id = d.folder_id AND m.user_id = ? AND m.status = 'ACTIVE'
`;
// Parameters: [userId, documentId].
const findDocumentQuery = `
  SELECT ${documentColumns}, m.role FROM Document AS d
  ${callerMembershipJoin} ${currentRevisionJoins}
  WHERE d.document_id = ?
`;

function parseJson(value) {
  return typeof value === 'string' ? JSON.parse(value) : value;
}

function toNumber(value) {
  return value === null || value === undefined ? null : Number(value);
}

function toDocument(row) {
  return { ...row, currentVersionNumber: toNumber(row.currentVersionNumber), ciphertextSize: toNumber(row.ciphertextSize) };
}

function toMysqlDateTime(date) {
  return date.toISOString().slice(0, -1).replace('T', ' ');
}

// Same rule as the folders module's cryptoState: no rotation job for the current
// policy (null) or a COMPLETED job means ready; a deletion operation never is.
async function readFolderState(executor, folderId) {
  const [[row]] = await executor.execute(`
    SELECT p.policyVersion,
           (SELECT j.status FROM Folder_Rotation_Job AS j
            WHERE j.folder_id = ? AND j.policy_version = p.policyVersion) AS rotationStatus,
           EXISTS (SELECT 1 FROM Folder_Deletion_Operation AS o WHERE o.folder_id = ?) AS deleting
    FROM (SELECT MAX(policy_version) AS policyVersion FROM Folder_Policy WHERE folder_id = ?) AS p
  `, [folderId, folderId, folderId]);
  const policyVersion = Number(row?.policyVersion ?? 0);
  const rotationStatus = row?.rotationStatus ?? null;
  const ready = policyVersion > 0 && Number(row?.deleting ?? 1) === 0
    && (rotationStatus === null || rotationStatus === 'COMPLETED');
  return { policyVersion, ready };
}

// Lock order for every write: Treatment_Folder, then Folder_Membership, then
// Upload_Context / Document. Matches the folders module.
async function lockMembership(connection, folderId, userId) {
  const [[folder]] = await connection.execute(
    'SELECT folder_id FROM Treatment_Folder WHERE folder_id = ? FOR UPDATE', [folderId],
  );
  if (!folder) return null;
  const [[membership]] = await connection.execute(`
    SELECT CAST(membership_id AS CHAR) AS membershipId, role, status
    FROM Folder_Membership WHERE folder_id = ? AND user_id = ? AND status = 'ACTIVE' FOR UPDATE
  `, [folderId, userId]);
  return membership ?? null;
}

async function findDocumentFolder(executor, documentId) {
  const [[row]] = await executor.execute(
    'SELECT folder_id AS folderId FROM Document WHERE document_id = ?', [documentId],
  );
  return row?.folderId ?? null;
}

function createMysqlDocumentRepository(pool, { keyDirectory, uploadContextTtlSeconds = 600 } = {}) {
  if (!keyDirectory) throw new Error('keyDirectory is required');

  async function inTransaction(operation) {
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      const result = await operation(connection);
      if (result.code) await connection.rollback();
      else await connection.commit();
      return result;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async function findReadableRevision(userId, versionId) {
    const [[version]] = await pool.execute(`
      SELECT v.version_id AS versionId, d.document_id AS documentId, d.folder_id AS folderId, m.role, m.status
      FROM Document_Version AS v INNER JOIN Document AS d ON d.document_id = v.document_id
      ${callerMembershipJoin}
      WHERE v.version_id = ?
    `, [userId, versionId]);
    if (!hasFolderPermission(version, 'read')) return { code: 'VERSION_NOT_FOUND' };
    const state = await readFolderState(pool, version.folderId);
    if (!state.ready) return { code: 'FOLDER_NOT_READY' };
    const [[revision]] = await pool.execute(`
      SELECT r.revision_id AS revisionId, r.storage_object_key AS objectKey,
             r.ciphertext_size AS ciphertextSize, r.signer_key_id AS signerKeyId,
             r.signed_manifest AS signedManifest
      FROM Crypto_Revision AS r WHERE r.version_id = ? AND r.status = 'ACTIVE'
    `, [versionId]);
    if (!revision) return { code: 'VERSION_NOT_FOUND' };
    return { version, revision };
  }

  return {
    async listDocumentsForUser(userId, folderId, { query = '', category, page = 1 } = {}) {
      const [[membership]] = await pool.execute(`
        SELECT role, status FROM Folder_Membership
        WHERE folder_id = ? AND user_id = ? AND status = 'ACTIVE'
      `, [folderId, userId]);
      if (!hasFolderPermission(membership, 'read')) return { code: 'FORBIDDEN' };
      const filters = ['d.folder_id = ?'];
      const values = [folderId];
      if (query) {
        filters.push("d.document_name LIKE ? ESCAPE '!'");
        values.push('%' + query.replace(/[!%_]/g, '!$&') + '%');
      }
      if (category) {
        filters.push('d.category = ?');
        values.push(category);
      }
      const [rows] = await pool.query(`
        SELECT ${documentColumns} FROM Document AS d ${currentRevisionJoins}
        WHERE ${filters.join(' AND ')}
        ORDER BY d.updated_at DESC, d.document_id
        LIMIT ? OFFSET ?
      `, [...values, PAGE_SIZE + 1, (page - 1) * PAGE_SIZE]);
      return {
        documents: rows.slice(0, PAGE_SIZE).map(toDocument),
        nextPage: rows.length > PAGE_SIZE ? page + 1 : null,
      };
    },

    async findDocumentForUser(userId, documentId) {
      const [[row]] = await pool.execute(findDocumentQuery, [userId, documentId]);
      return row ? toDocument(row) : null;
    },

    async listVersionsForUser(userId, documentId) {
      const [[document]] = await pool.execute(`
        SELECT d.current_version_id AS currentVersionId FROM Document AS d
        ${callerMembershipJoin}
        WHERE d.document_id = ?
      `, [userId, documentId]);
      if (!document) return null;
      const [rows] = await pool.execute(`
        SELECT v.version_id AS versionId, v.version_number AS versionNumber,
               v.base_version_id AS baseVersionId, CAST(v.created_by AS CHAR) AS createdBy,
               v.mime_type AS mimeType, r.ciphertext_size AS ciphertextSize, v.created_at AS createdAt
        FROM Document_Version AS v
        LEFT JOIN Crypto_Revision AS r ON r.version_id = v.version_id AND r.status = 'ACTIVE'
        WHERE v.document_id = ?
        ORDER BY v.version_number DESC
      `, [documentId]);
      return {
        versions: rows.map((row) => ({
          ...row,
          ciphertextSize: toNumber(row.ciphertextSize),
          isCurrent: row.versionId === document.currentVersionId,
        })),
      };
    },

    async getVersionManifestForUser(userId, versionId) {
      const access = await findReadableRevision(userId, versionId);
      if (access.code) return access;
      const { version, revision } = access;
      const [[envelope]] = await pool.execute(`
        SELECT recipient_key_id AS keyId, wrapped_dek AS wrappedDek
        FROM DEK_Envelope WHERE revision_id = ? AND recipient_user_id = ?
      `, [revision.revisionId, userId]);
      if (!envelope) return { code: 'ENVELOPE_NOT_AVAILABLE' };
      const signer = await keyDirectory.getSigningKeyById(pool, revision.signerKeyId);
      const { manifest, signature } = parseJson(revision.signedManifest);
      return {
        versionId: version.versionId,
        documentId: version.documentId,
        folderId: version.folderId,
        revisionId: revision.revisionId,
        manifest,
        signature,
        signer: { userId: signer.userId, keyId: signer.keyId, publicKeyJwk: signer.publicKeyJwk },
        envelope: { keyId: envelope.keyId, wrappedDek: Buffer.from(envelope.wrappedDek).toString('base64url') },
      };
    },

    async getVersionContentForUser(userId, versionId, revisionId) {
      const access = await findReadableRevision(userId, versionId);
      if (access.code) return access;
      const { revision } = access;
      if (revisionId && revisionId !== revision.revisionId) {
        return { code: 'REVISION_CHANGED', revisionId: revision.revisionId };
      }
      return { revisionId: revision.revisionId, objectKey: revision.objectKey, ciphertextSize: Number(revision.ciphertextSize) };
    },
  };
}

module.exports = { createMysqlDocumentRepository };
```

Note: `randomUUID`, `verifyDocumentUpload`, `toMysqlDateTime`, `lockMembership`, `findDocumentFolder` and `inTransaction` are used in Tasks 7–8. Keep them.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && npm test`
Expected: PASS, 30 tests.

- [ ] **Step 6: Commit**

```bash
git add backend/src/documents/mysql-document-repository.js backend/test/mysql-document-repository.test.js backend/test/helpers/fake-mysql.js
git commit -m "Add document repository reads with folder readiness checks"
```

---

### Task 7: Document repository: upload contexts and publishing

**Files:**
- Modify: `src/documents/mysql-document-repository.js`
- Test: `test/mysql-document-repository.test.js` (append)

**Interfaces:**
- Consumes: `verifyDocumentUpload` (Task 5); key directory `getActiveSigningKey`, `getActiveEncryptionKey` (Task 4); helpers from Task 6.
- Produces repository methods:
  - `createUploadContext(userId, folderId, { purpose: 'NEW_DOCUMENT' } | { purpose: 'NEW_VERSION', documentId, baseVersionId }) → { contextId, purpose, folderId, documentId, versionId, revisionId, versionNumber, baseVersionId, policyVersion, signerKeyId, expiresAt, recipients: [{ userId, membershipId, keyId, fingerprint, publicKeyJwk }] } | { code, ... }` (codes: `FORBIDDEN`, `FOLDER_NOT_READY`, `SIGNING_KEY_MISSING`, `DOCUMENT_NOT_FOUND`, `VERSION_CONFLICT` + `currentVersionId`, `RECIPIENT_KEY_MISSING` + `userIds`).
  - `publishUpload({ userId, purpose, folderId?, documentId?, contextId, documentName?, category?, mimeType, manifest, signature, envelopes, objectKey, ciphertextSize, ciphertextSha256 }) → { documentId, versionId, revisionId, versionNumber } | { code, ... }` (`folderId` for `NEW_DOCUMENT`, `documentId` for `NEW_VERSION`).

- [ ] **Step 1: Write the failing tests**

Append to `test/mysql-document-repository.test.js` (add the fixtures import at the top of the file):
```js
const { createSignedUpload, createSigner, createUploadContextFixture, sha256Hex } = require('./helpers/document-fixtures');

test('upload contexts lock the folder, check the base version and snapshot recipient keys', async () => {
  const state = { currentVersionId: versionId, missingKeyFor: null };
  const { pool, events } = createFakeMysql((sql, args, events) => {
    if (sql.includes('FROM Treatment_Folder')) {
      assert.match(sql, /FOR UPDATE$/);
      events.push('lock folder');
      return [[{ folder_id: folderId }]];
    }
    if (sql.includes('FROM Folder_Membership WHERE folder_id = ? AND user_id = ?')) {
      events.push('lock membership');
      return [[{ membershipId: '70', role: args[1] === '7' ? 'EDITOR' : 'VIEWER', status: 'ACTIVE' }]];
    }
    if (sql.includes('FROM Folder_Policy')) return [[{ policyVersion: 3, rotationStatus: 'COMPLETED', deleting: 0 }]];
    if (sql.includes('FROM Document WHERE document_id = ? AND folder_id = ?')) {
      assert.match(sql, /FOR UPDATE$/);
      events.push('lock document');
      return [[{ currentVersionId: state.currentVersionId }]];
    }
    if (sql.includes('MAX(version_number)')) return [[{ versionNumber: 4 }]];
    if (sql.includes("FROM Folder_Membership WHERE folder_id = ? AND status = 'ACTIVE' ORDER BY user_id")) {
      return [[{ membershipId: '70', userId: '7' }, { membershipId: '90', userId: '9' }]];
    }
    assert.match(sql, /^INSERT INTO Upload_Context/);
    events.push('insert context');
    const recipients = JSON.parse(args[11]);
    assert.deepEqual(recipients.map(({ userId }) => userId), ['7', '9']);
    assert.equal(recipients.some((recipient) => 'publicKeyJwk' in recipient), false);
    return [{ affectedRows: 1 }];
  });
  const keyDirectory = {
    async getActiveSigningKey(_connection, userId) { return { keyId: 'sign-' + userId }; },
    async getActiveEncryptionKey(_connection, userId) {
      return userId === state.missingKeyFor ? null : { keyId: 'enc-' + userId, fingerprint: 'f' + userId, publicKeyJwk: { kty: 'RSA', n: userId, e: 'AQAB' } };
    },
  };
  const repository = createMysqlDocumentRepository(pool, { keyDirectory, uploadContextTtlSeconds: 600 });
  const request = { purpose: 'NEW_VERSION', documentId, baseVersionId: versionId };
  const context = await repository.createUploadContext('7', folderId, request);
  assert.deepEqual(events, ['begin', 'lock folder', 'lock membership', 'lock document', 'insert context', 'commit', 'release']);
  assert.equal(context.documentId, documentId);
  assert.equal(context.baseVersionId, versionId);
  assert.equal(context.versionNumber, 5);
  assert.equal(context.policyVersion, 3);
  assert.equal(context.signerKeyId, 'sign-7');
  assert.ok(Date.parse(context.expiresAt) > Date.now() + 590_000);
  assert.deepEqual(context.recipients, [
    { userId: '7', membershipId: '70', keyId: 'enc-7', fingerprint: 'f7', publicKeyJwk: { kty: 'RSA', n: '7', e: 'AQAB' } },
    { userId: '9', membershipId: '90', keyId: 'enc-9', fingerprint: 'f9', publicKeyJwk: { kty: 'RSA', n: '9', e: 'AQAB' } },
  ]);
  events.length = 0;
  assert.deepEqual(await repository.createUploadContext('8', folderId, request), { code: 'FORBIDDEN' });
  assert.deepEqual(events.slice(-2), ['rollback', 'release']);
  state.currentVersionId = 'newer';
  assert.deepEqual(await repository.createUploadContext('7', folderId, request), { code: 'VERSION_CONFLICT', currentVersionId: 'newer' });
  state.missingKeyFor = '9';
  assert.deepEqual(await repository.createUploadContext('7', folderId, { purpose: 'NEW_DOCUMENT' }), { code: 'RECIPIENT_KEY_MISSING', userIds: ['9'] });
});

test('publishing a new version re-checks the context under lock and rejects stale state', async () => {
  const signer = await createSigner();
  const context = createUploadContextFixture({ purpose: 'NEW_VERSION', folderId, documentId, baseVersionId: versionId, versionNumber: 2 });
  const upload = await createSignedUpload(context, signer);
  const state = { currentVersionId: versionId, policyVersion: context.policyVersion, consumedAt: null };
  const { pool, events } = createFakeMysql((sql, args, events) => {
    if (sql === 'SELECT folder_id AS folderId FROM Document WHERE document_id = ?') return [[{ folderId }]];
    if (sql.includes('FROM Treatment_Folder')) {
      events.push('lock folder');
      return [[{ folder_id: folderId }]];
    }
    if (sql.includes('FROM Folder_Membership WHERE folder_id = ? AND user_id = ?')) {
      events.push('lock membership');
      return [[{ membershipId: '70', role: 'EDITOR', status: 'ACTIVE' }]];
    }
    if (sql.includes('FROM Upload_Context')) {
      assert.match(sql, /FOR UPDATE$/);
      assert.deepEqual(args, [context.contextId, folderId, '7']);
      events.push('lock context');
      return [[{ ...context, recipients: JSON.stringify(context.recipients), consumedAt: state.consumedAt, expired: 0 }]];
    }
    if (sql.includes('FROM Folder_Policy')) return [[{ policyVersion: state.policyVersion, rotationStatus: null, deleting: 0 }]];
    if (sql.startsWith('SELECT current_version_id AS currentVersionId FROM Document')) {
      assert.match(sql, /FOR UPDATE$/);
      events.push('lock document');
      return [[{ currentVersionId: state.currentVersionId }]];
    }
    if (sql.startsWith('INSERT INTO Document_Version')) {
      events.push('insert version');
      assert.deepEqual(args, [context.versionId, documentId, 2, versionId, '7', context.signerKeyId, 'application/pdf']);
    } else if (sql.startsWith('INSERT INTO Crypto_Revision')) {
      events.push('insert revision');
      assert.equal(args[2], `${context.revisionId}/object`);
      assert.equal(args[5].length, 12);
    } else if (sql.startsWith('INSERT INTO DEK_Envelope')) {
      events.push('insert envelope ' + args[1]);
      assert.equal(args[4].length, 384);
    } else if (sql.startsWith('UPDATE Document SET current_version_id')) {
      events.push('set current');
    } else {
      assert.match(sql, /^UPDATE Upload_Context SET consumed_at/);
      events.push('consume');
    }
    return [{ affectedRows: 1 }];
  });
  const keyDirectory = {
    async getActiveSigningKey() { return { keyId: context.signerKeyId, publicKeyJwk: signer.publicKeyJwk }; },
    async getActiveEncryptionKey(_connection, userId) {
      return { keyId: context.recipients.find((recipient) => recipient.userId === userId).keyId };
    },
  };
  const repository = createMysqlDocumentRepository(pool, { keyDirectory });
  const input = {
    userId: '7', purpose: 'NEW_VERSION', documentId, contextId: context.contextId, mimeType: 'application/pdf',
    manifest: upload.manifest, signature: upload.signature, envelopes: upload.envelopes,
    objectKey: `${context.revisionId}/object`, ciphertextSize: upload.ciphertext.length,
    ciphertextSha256: sha256Hex(upload.ciphertext),
  };
  assert.deepEqual(await repository.publishUpload(input), {
    documentId, versionId: context.versionId, revisionId: context.revisionId, versionNumber: 2,
  });
  assert.deepEqual(events, [
    'begin', 'lock folder', 'lock membership', 'lock context', 'lock document', 'insert version',
    'insert revision', 'insert envelope 7', 'insert envelope 9', 'set current', 'consume', 'commit', 'release',
  ]);
  const failures = [
    [{ currentVersionId: 'newer' }, { code: 'VERSION_CONFLICT', currentVersionId: 'newer' }],
    [{ currentVersionId: versionId, policyVersion: context.policyVersion + 1 }, { code: 'CONTEXT_STALE' }],
    [{ policyVersion: context.policyVersion, consumedAt: new Date() }, { code: 'CONTEXT_USED' }],
  ];
  for (const [change, expected] of failures) {
    Object.assign(state, change);
    events.length = 0;
    assert.deepEqual(await repository.publishUpload(input), expected);
    assert.equal(events.some((event) => event.startsWith('insert')), false);
    assert.deepEqual(events.slice(-2), ['rollback', 'release']);
  }
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && node --test test/mysql-document-repository.test.js`
Expected: FAIL with `repository.createUploadContext is not a function`.

- [ ] **Step 3: Implement**

Add above `function createMysqlDocumentRepository` in `src/documents/mysql-document-repository.js`:
```js
const contextColumns = `
  context_id AS contextId, purpose, folder_id AS folderId, CAST(user_id AS CHAR) AS userId,
  document_id AS documentId, version_id AS versionId, revision_id AS revisionId,
  base_version_id AS baseVersionId, version_number AS versionNumber,
  policy_version AS policyVersion, signer_key_id AS signerKeyId, recipients,
  consumed_at AS consumedAt, expires_at <= UTC_TIMESTAMP(3) AS expired
`;

async function issueUploadContext(connection, { userId, folderId, request, keyDirectory, ttlSeconds }) {
  const membership = await lockMembership(connection, folderId, userId);
  if (!hasFolderPermission(membership, 'upload')) return { code: 'FORBIDDEN' };
  const state = await readFolderState(connection, folderId);
  if (!state.ready) return { code: 'FOLDER_NOT_READY' };
  const signer = await keyDirectory.getActiveSigningKey(connection, userId);
  if (!signer) return { code: 'SIGNING_KEY_MISSING' };
  let documentId = randomUUID();
  let versionNumber = 1;
  let baseVersionId = null;
  if (request.purpose === 'NEW_VERSION') {
    const [[document]] = await connection.execute(`
      SELECT current_version_id AS currentVersionId FROM Document
      WHERE document_id = ? AND folder_id = ? FOR UPDATE
    `, [request.documentId, folderId]);
    if (!document) return { code: 'DOCUMENT_NOT_FOUND' };
    if (document.currentVersionId !== request.baseVersionId) {
      return { code: 'VERSION_CONFLICT', currentVersionId: document.currentVersionId };
    }
    const [[latest]] = await connection.execute(
      'SELECT MAX(version_number) AS versionNumber FROM Document_Version WHERE document_id = ?', [request.documentId],
    );
    documentId = request.documentId;
    versionNumber = Number(latest.versionNumber) + 1;
    baseVersionId = request.baseVersionId;
  }
  const [members] = await connection.execute(`
    SELECT CAST(membership_id AS CHAR) AS membershipId, CAST(user_id AS CHAR) AS userId
    FROM Folder_Membership WHERE folder_id = ? AND status = 'ACTIVE' ORDER BY user_id
  `, [folderId]);
  const recipients = [];
  const missing = [];
  for (const member of members) {
    const key = await keyDirectory.getActiveEncryptionKey(connection, member.userId);
    if (!key) missing.push(member.userId);
    else recipients.push({ userId: member.userId, membershipId: member.membershipId, keyId: key.keyId, fingerprint: key.fingerprint, publicKeyJwk: key.publicKeyJwk });
  }
  if (missing.length) return { code: 'RECIPIENT_KEY_MISSING', userIds: missing };
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
  const context = {
    contextId: randomUUID(), purpose: request.purpose, folderId, documentId,
    versionId: randomUUID(), revisionId: randomUUID(), versionNumber, baseVersionId,
    policyVersion: state.policyVersion, signerKeyId: signer.keyId, expiresAt: expiresAt.toISOString(),
  };
  const storedRecipients = recipients.map(({ publicKeyJwk, ...recipient }) => recipient);
  await connection.execute(`
    INSERT INTO Upload_Context (context_id, folder_id, user_id, purpose, document_id, version_id,
      revision_id, base_version_id, version_number, policy_version, signer_key_id, recipients, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [
    context.contextId, folderId, userId, context.purpose, documentId, context.versionId,
    context.revisionId, baseVersionId, versionNumber, context.policyVersion, signer.keyId,
    JSON.stringify(storedRecipients), toMysqlDateTime(expiresAt),
  ]);
  return { ...context, recipients };
}

async function publishVersion(connection, input, keyDirectory) {
  const { userId, purpose } = input;
  const hidden = purpose === 'NEW_VERSION' ? { code: 'DOCUMENT_NOT_FOUND' } : { code: 'FORBIDDEN' };
  const folderId = purpose === 'NEW_VERSION' ? await findDocumentFolder(connection, input.documentId) : input.folderId;
  if (!folderId) return hidden;
  const membership = await lockMembership(connection, folderId, userId);
  if (!membership) return hidden;
  if (!hasFolderPermission(membership, 'upload')) return { code: 'FORBIDDEN' };
  const [[stored]] = await connection.execute(`
    SELECT ${contextColumns} FROM Upload_Context
    WHERE context_id = ? AND folder_id = ? AND user_id = ? FOR UPDATE
  `, [input.contextId, folderId, userId]);
  if (!stored || stored.purpose !== purpose
      || (purpose === 'NEW_VERSION' && stored.documentId !== input.documentId)) {
    return { code: 'CONTEXT_NOT_FOUND' };
  }
  if (stored.consumedAt) return { code: 'CONTEXT_USED' };
  if (Number(stored.expired)) return { code: 'CONTEXT_EXPIRED' };
  const context = { ...stored, recipients: parseJson(stored.recipients) };
  const state = await readFolderState(connection, folderId);
  if (!state.ready) return { code: 'FOLDER_NOT_READY' };
  if (state.policyVersion !== Number(context.policyVersion)) return { code: 'CONTEXT_STALE' };
  const signer = await keyDirectory.getActiveSigningKey(connection, userId);
  if (!signer || signer.keyId !== context.signerKeyId) return { code: 'SIGNING_KEY_MISSING' };
  for (const recipient of context.recipients) {
    const key = await keyDirectory.getActiveEncryptionKey(connection, recipient.userId);
    if (key?.keyId !== recipient.keyId) return { code: 'CONTEXT_STALE' };
  }
  const verified = verifyDocumentUpload({
    context,
    manifest: input.manifest,
    signature: input.signature,
    envelopes: input.envelopes,
    signerPublicJwk: signer.publicKeyJwk,
    ciphertext: { sha256: input.ciphertextSha256, size: input.ciphertextSize },
  });
  if (verified.code) return verified;
  if (purpose === 'NEW_VERSION') {
    const [[document]] = await connection.execute(
      'SELECT current_version_id AS currentVersionId FROM Document WHERE document_id = ? FOR UPDATE', [context.documentId],
    );
    if (!document) return { code: 'DOCUMENT_NOT_FOUND' };
    if (document.currentVersionId !== context.baseVersionId) {
      return { code: 'VERSION_CONFLICT', currentVersionId: document.currentVersionId };
    }
  } else {
    await connection.execute(`
      INSERT INTO Document (document_id, folder_id, document_name, category, original_uploader_id)
      VALUES (?, ?, ?, ?, ?)
    `, [context.documentId, folderId, input.documentName, input.category, userId]);
  }
  const versionNumber = Number(context.versionNumber);
  await connection.execute(`
    INSERT INTO Document_Version (version_id, document_id, version_number, base_version_id,
      created_by, author_key_id, mime_type)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `, [context.versionId, context.documentId, versionNumber, context.baseVersionId, userId, signer.keyId, input.mimeType]);
  await connection.execute(`
    INSERT INTO Crypto_Revision (revision_id, version_id, revision_number, status, storage_object_key,
      ciphertext_size, ciphertext_sha256, nonce, policy_version, signed_manifest, signer_key_id,
      created_by, activated_at)
    VALUES (?, ?, 1, 'ACTIVE', ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(3))
  `, [
    context.revisionId, context.versionId, input.objectKey, input.ciphertextSize, input.ciphertextSha256,
    verified.nonce, Number(context.policyVersion), JSON.stringify({ manifest: input.manifest, signature: input.signature }),
    signer.keyId, userId,
  ]);
  for (const envelope of verified.envelopes) {
    await connection.execute(`
      INSERT INTO DEK_Envelope (revision_id, recipient_user_id, recipient_membership_id, recipient_key_id, wrapped_dek)
      VALUES (?, ?, ?, ?, ?)
    `, [context.revisionId, envelope.userId, envelope.membershipId, envelope.keyId, envelope.wrappedDek]);
  }
  await connection.execute(
    'UPDATE Document SET current_version_id = ?, updated_at = UTC_TIMESTAMP(3) WHERE document_id = ?',
    [context.versionId, context.documentId],
  );
  const [consumed] = await connection.execute(
    'UPDATE Upload_Context SET consumed_at = UTC_TIMESTAMP(3) WHERE context_id = ? AND consumed_at IS NULL',
    [context.contextId],
  );
  if (consumed.affectedRows !== 1) throw new Error('Upload context was consumed concurrently');
  return { documentId: context.documentId, versionId: context.versionId, revisionId: context.revisionId, versionNumber };
}
```

Add to the object returned by `createMysqlDocumentRepository`:
```js
    createUploadContext(userId, folderId, request) {
      return inTransaction((connection) => issueUploadContext(connection, {
        userId, folderId, request, keyDirectory, ttlSeconds: uploadContextTtlSeconds,
      }));
    },

    publishUpload(input) {
      return inTransaction((connection) => publishVersion(connection, input, keyDirectory));
    },
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && npm test`
Expected: PASS, 32 tests.

- [ ] **Step 5: Commit**

```bash
git add backend/src/documents/mysql-document-repository.js backend/test/mysql-document-repository.test.js
git commit -m "Issue upload contexts and publish verified document versions"
```

---

### Task 8: Document repository: metadata update and deletion

**Files:**
- Modify: `src/documents/mysql-document-repository.js`
- Test: `test/mysql-document-repository.test.js` (append)

**Interfaces:**
- Produces repository methods:
  - `updateDocumentMetadata(userId, documentId, { documentName?, category? }) → Document & { role } | { code: 'DOCUMENT_NOT_FOUND' | 'FORBIDDEN' }`
  - `deleteDocument(userId, documentId) → { objectKeys: string[] } | { code: 'DOCUMENT_NOT_FOUND' | 'FORBIDDEN' | 'FOLDER_NOT_READY' }`. The caller deletes the returned objects from storage after the commit.

- [ ] **Step 1: Write the failing tests**

Append to `test/mysql-document-repository.test.js`:
```js
function documentAccessHandler(roles, extra) {
  return (sql, args, events) => {
    if (sql === 'SELECT folder_id AS folderId FROM Document WHERE document_id = ?') return [[{ folderId }]];
    if (sql.includes('FROM Treatment_Folder')) return [[{ folder_id: folderId }]];
    if (sql.includes('FROM Folder_Membership WHERE folder_id = ? AND user_id = ?')) {
      return [roles[args[1]] ? [{ membershipId: '1', role: roles[args[1]], status: 'ACTIVE' }] : []];
    }
    if (sql.includes('FROM Folder_Policy')) return [[{ policyVersion: 2, rotationStatus: null, deleting: 0 }]];
    if (sql.startsWith('SELECT document_id FROM Document')) {
      assert.match(sql, /FOR UPDATE$/);
      return [[{ document_id: documentId }]];
    }
    return extra(sql, args, events);
  };
}

test('metadata updates re-check the editor role and change only display fields', async () => {
  const roles = { 5: 'OWNER', 7: 'EDITOR', 8: 'VIEWER' };
  let update;
  const { pool } = createFakeMysql(documentAccessHandler(roles, (sql, args) => {
    if (sql.startsWith('UPDATE Document SET')) {
      update = { sql, args };
      return [{ affectedRows: 1 }];
    }
    assert.match(sql, /m\.role FROM Document AS d/);
    return [[{ documentId, documentName: 'Đơn thuốc', category: 'PRESCRIPTION', role: roles[args[0]], currentVersionNumber: 1, ciphertextSize: '64' }]];
  }));
  const repository = createMysqlDocumentRepository(pool, { keyDirectory: {} });
  assert.deepEqual(await repository.updateDocumentMetadata('8', documentId, { documentName: 'X' }), { code: 'FORBIDDEN' });
  assert.deepEqual(await repository.updateDocumentMetadata('9', documentId, { documentName: 'X' }), { code: 'DOCUMENT_NOT_FOUND' });
  assert.equal(update, undefined);
  const result = await repository.updateDocumentMetadata('7', documentId, { documentName: 'Đơn thuốc', category: 'PRESCRIPTION' });
  assert.equal(update.sql, 'UPDATE Document SET document_name = ?, category = ?, updated_at = UTC_TIMESTAMP(3) WHERE document_id = ?');
  assert.deepEqual(update.args, ['Đơn thuốc', 'PRESCRIPTION', documentId]);
  assert.equal(result.role, 'EDITOR');
  assert.equal(result.ciphertextSize, 64);
});

test('document deletion is owner-only and removes rows children-first', async () => {
  const roles = { 5: 'OWNER', 7: 'EDITOR' };
  const { pool, events } = createFakeMysql(documentAccessHandler(roles, (sql, _args, events) => {
    if (sql.startsWith('SELECT r.storage_object_key')) return [[{ objectKey: 'a/1' }, { objectKey: 'b/2' }]];
    if (sql.startsWith('DELETE FROM Document_Version')) assert.match(sql, /ORDER BY version_number DESC$/);
    events.push(sql.split(' ').slice(0, 3).join(' '));
    return [{ affectedRows: 1 }];
  }));
  const repository = createMysqlDocumentRepository(pool, { keyDirectory: {} });
  assert.deepEqual(await repository.deleteDocument('7', documentId), { code: 'FORBIDDEN' });
  assert.deepEqual(await repository.deleteDocument('9', documentId), { code: 'DOCUMENT_NOT_FOUND' });
  events.length = 0;
  assert.deepEqual(await repository.deleteDocument('5', documentId), { objectKeys: ['a/1', 'b/2'] });
  assert.deepEqual(events, [
    'begin', 'DELETE e FROM', 'DELETE r FROM', 'UPDATE Document SET', 'DELETE FROM Document_Version',
    'DELETE FROM Upload_Context', 'DELETE FROM Document', 'commit', 'release',
  ]);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && node --test test/mysql-document-repository.test.js`
Expected: FAIL with `repository.updateDocumentMetadata is not a function`.

- [ ] **Step 3: Implement**

Add above `function createMysqlDocumentRepository`:
```js
// Shared start of document writes: find the folder, lock folder + membership,
// check the role, then lock the document row.
async function lockDocumentForAction(connection, userId, documentId, action) {
  const folderId = await findDocumentFolder(connection, documentId);
  if (!folderId) return { code: 'DOCUMENT_NOT_FOUND' };
  const membership = await lockMembership(connection, folderId, userId);
  if (!membership) return { code: 'DOCUMENT_NOT_FOUND' };
  if (!hasFolderPermission(membership, action)) return { code: 'FORBIDDEN' };
  const [[document]] = await connection.execute(
    'SELECT document_id FROM Document WHERE document_id = ? FOR UPDATE', [documentId],
  );
  if (!document) return { code: 'DOCUMENT_NOT_FOUND' };
  return { folderId };
}

async function updateMetadata(connection, userId, documentId, changes) {
  const locked = await lockDocumentForAction(connection, userId, documentId, 'updateDocument');
  if (locked.code) return locked;
  const columns = [];
  const values = [];
  if (changes.documentName !== undefined) {
    columns.push('document_name = ?');
    values.push(changes.documentName);
  }
  if (changes.category !== undefined) {
    columns.push('category = ?');
    values.push(changes.category);
  }
  await connection.execute(
    `UPDATE Document SET ${columns.join(', ')}, updated_at = UTC_TIMESTAMP(3) WHERE document_id = ?`,
    [...values, documentId],
  );
  const [[row]] = await connection.execute(findDocumentQuery, [userId, documentId]);
  return toDocument(row);
}

async function removeDocument(connection, userId, documentId) {
  const locked = await lockDocumentForAction(connection, userId, documentId, 'deleteDocument');
  if (locked.code) return locked;
  const state = await readFolderState(connection, locked.folderId);
  if (!state.ready) return { code: 'FOLDER_NOT_READY' };
  const [objects] = await connection.execute(`
    SELECT r.storage_object_key AS objectKey FROM Crypto_Revision AS r
    INNER JOIN Document_Version AS v ON v.version_id = r.version_id
    WHERE v.document_id = ?
  `, [documentId]);
  await connection.execute(`
    DELETE e FROM DEK_Envelope AS e
    INNER JOIN Crypto_Revision AS r ON r.revision_id = e.revision_id
    INNER JOIN Document_Version AS v ON v.version_id = r.version_id
    WHERE v.document_id = ?
  `, [documentId]);
  await connection.execute(`
    DELETE r FROM Crypto_Revision AS r
    INNER JOIN Document_Version AS v ON v.version_id = r.version_id
    WHERE v.document_id = ?
  `, [documentId]);
  await connection.execute('UPDATE Document SET current_version_id = NULL WHERE document_id = ?', [documentId]);
  // Newest first, so base_version_id references never point at an already deleted row.
  await connection.execute('DELETE FROM Document_Version WHERE document_id = ? ORDER BY version_number DESC', [documentId]);
  await connection.execute('DELETE FROM Upload_Context WHERE document_id = ?', [documentId]);
  await connection.execute('DELETE FROM Document WHERE document_id = ?', [documentId]);
  return { objectKeys: objects.map(({ objectKey }) => objectKey) };
}
```

Add to the returned object:
```js
    updateDocumentMetadata(userId, documentId, changes) {
      return inTransaction((connection) => updateMetadata(connection, userId, documentId, changes));
    },

    deleteDocument(userId, documentId) {
      return inTransaction((connection) => removeDocument(connection, userId, documentId));
    },
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && npm test`
Expected: PASS, 34 tests.

- [ ] **Step 5: Commit**

```bash
git add backend/src/documents/mysql-document-repository.js backend/test/mysql-document-repository.test.js
git commit -m "Update document metadata and delete documents with all versions"
```

---
### Task 9: Document router and server wiring

**Files:**
- Create: `src/documents/document-router.js`
- Modify: `src/server.js` (additions only)
- Test: `test/documents.test.js`

**Interfaces:**
- Consumes: repository methods from Tasks 6–8 (exact names and shapes there); object storage `put/get/delete` (Task 3).
- Produces: `createDocumentRouter({ authenticate, documentRepository, objectStorage, maxUploadBytes }) → express.Router` mounted at `/api/v1`. `createApp` accepts new options `documentRepository`, `objectStorage`, `keyDirectory`, `maxUploadBytes`, `uploadContextTtlSeconds`. When `mysqlPool` and `keyDirectory` are given and `documentRepository` is not, `createApp` builds the MySQL document repository. `keyDirectory` also becomes the default `folderPolicyKeys`.

- [ ] **Step 1: Write the failing tests**

`test/documents.test.js`:
```js
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const { once } = require('node:events');
const { test } = require('node:test');
const { createApp } = require('../src/server');

const folderId = randomUUID();
const documentId = randomUUID();
const versionId = randomUUID();
const revisionId = randomUUID();

function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

function createMemoryStorage() {
  const objects = new Map();
  return {
    objects,
    async put(key, data) { objects.set(key, Buffer.from(data)); },
    async get(key) {
      if (!objects.has(key)) throw Object.assign(new Error('missing'), { code: 'ENOENT' });
      return objects.get(key);
    },
    async delete(key) { objects.delete(key); },
  };
}

async function startApp(t, options) {
  const app = createApp({
    authenticate(request, _response, next) {
      const id = request.get('x-test-user');
      if (id) request.user = { id };
      next();
    },
    ...options,
  });
  const server = app.listen(0, '127.0.0.1');
  t.after(() => server.close());
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}/api/v1`;
  return (path, { user = '7', headers = {}, ...init } = {}) => fetch(base + path, {
    ...init,
    headers: { ...(user ? { 'x-test-user': user } : {}), ...headers },
  });
}

function uploadForm({ ciphertext = Buffer.alloc(32, 1), manifest = {}, metadata = {} } = {}) {
  const form = new FormData();
  form.append('metadata', JSON.stringify({
    contextId: randomUUID(),
    documentName: '  Xét nghiệm máu  ',
    category: 'LABORATORY_RESULT',
    mimeType: 'application/pdf',
    signature: 'sig',
    envelopes: [],
    manifest: { revisionId, ciphertextSha256: sha256Hex(ciphertext), ciphertextSize: ciphertext.length, ...manifest },
    ...metadata,
  }));
  form.append('ciphertext', new Blob([ciphertext]), 'ciphertext.bin');
  return form;
}

test('document routes require an authenticated user and configured services', async (t) => {
  const call = await startApp(t, { documentRepository: {}, objectStorage: createMemoryStorage() });
  const anonymous = await call(`/documents/${documentId}`, { user: null });
  assert.equal(anonymous.status, 401);
  assert.equal(anonymous.headers.get('cache-control'), 'no-store');
  assert.equal((await call('/documents/not-a-uuid')).status, 400);
  const unconfigured = await startApp(t, { documentRepository: {} });
  const response = await unconfigured(`/documents/${documentId}`);
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { code: 'DOCUMENT_SERVICE_UNAVAILABLE' });
});

test('document lists validate filters and map repository results', async (t) => {
  const calls = [];
  const call = await startApp(t, {
    objectStorage: createMemoryStorage(),
    documentRepository: {
      async listDocumentsForUser(userId, id, filters) {
        calls.push([userId, id, filters]);
        return id === folderId ? { documents: [], nextPage: null } : { code: 'FORBIDDEN' };
      },
    },
  });
  const ok = await call(`/folders/${folderId}/documents?query=%20x%20&category=PRESCRIPTION&page=2`);
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get('cache-control'), 'no-store');
  assert.deepEqual(await ok.json(), { documents: [], nextPage: null });
  assert.deepEqual(calls, [['7', folderId, { query: 'x', category: 'PRESCRIPTION', page: 2 }]]);
  assert.equal((await call(`/folders/${folderId}/documents?page=0`)).status, 400);
  assert.equal((await call(`/folders/${folderId}/documents?category=BAD`)).status, 400);
  assert.equal((await call(`/folders/${folderId}/documents?query=${'a'.repeat(101)}`)).status, 400);
  assert.equal((await call('/folders/not-a-uuid/documents')).status, 403);
  assert.equal((await call(`/folders/${randomUUID()}/documents`)).status, 403);
  assert.equal(calls.length, 2);
});

test('upload contexts accept only the documented request shapes', async (t) => {
  const calls = [];
  const call = await startApp(t, {
    objectStorage: createMemoryStorage(),
    documentRepository: {
      async createUploadContext(userId, id, request) {
        calls.push([userId, id, request]);
        return request.purpose === 'NEW_DOCUMENT'
          ? { contextId: 'c1', recipients: [] }
          : { code: 'RECIPIENT_KEY_MISSING', userIds: ['9'] };
      },
    },
  });
  const post = (body, headers = { 'content-type': 'application/json' }) => call(`/folders/${folderId}/upload-contexts`, {
    method: 'POST', headers, body: typeof body === 'string' ? body : JSON.stringify(body),
  });
  const created = await post({ purpose: 'NEW_DOCUMENT' });
  assert.equal(created.status, 201);
  assert.deepEqual(await created.json(), { contextId: 'c1', recipients: [] });
  const missing = await post({ purpose: 'NEW_VERSION', documentId, baseVersionId: versionId });
  assert.equal(missing.status, 409);
  assert.deepEqual(await missing.json(), { code: 'RECIPIENT_KEY_MISSING', userIds: ['9'] });
  for (const body of [
    {}, { purpose: 'NEW_DOCUMENT', extra: 1 }, { purpose: 'NEW_VERSION', documentId },
    { purpose: 'NEW_VERSION', documentId: 'x', baseVersionId: versionId }, { purpose: 'OTHER' }, [],
  ]) {
    const response = await post(body);
    assert.equal(response.status, 400, JSON.stringify(body));
    assert.deepEqual(await response.json(), { code: 'INVALID_UPLOAD_CONTEXT_INPUT' });
  }
  const badJson = await post('{');
  assert.equal(badJson.status, 400);
  assert.deepEqual(await badJson.json(), { code: 'INVALID_JSON' });
  assert.deepEqual(calls, [
    ['7', folderId, { purpose: 'NEW_DOCUMENT' }],
    ['7', folderId, { purpose: 'NEW_VERSION', documentId, baseVersionId: versionId }],
  ]);
});

test('uploads store ciphertext before publishing and discard it when publishing fails', async (t) => {
  const storage = createMemoryStorage();
  const inputs = [];
  const call = await startApp(t, {
    objectStorage: storage,
    documentRepository: {
      async publishUpload(input) {
        inputs.push(input);
        assert.ok(storage.objects.has(input.objectKey), 'ciphertext is stored before publishing');
        if (input.purpose === 'NEW_VERSION') return { code: 'VERSION_CONFLICT', currentVersionId: 'v9' };
        if (input.mimeType === 'application/x-explode') throw new Error('database down');
        return { documentId, versionId, revisionId: input.manifest.revisionId, versionNumber: 1 };
      },
    },
  });
  const ciphertext = Buffer.alloc(32, 1);
  const created = await call(`/folders/${folderId}/documents`, { method: 'POST', body: uploadForm({ ciphertext }) });
  assert.equal(created.status, 201);
  assert.equal(created.headers.get('location'), `/api/v1/documents/${documentId}`);
  assert.deepEqual(await created.json(), { documentId, versionId, revisionId, versionNumber: 1 });
  const [first] = inputs;
  assert.equal(first.userId, '7');
  assert.equal(first.purpose, 'NEW_DOCUMENT');
  assert.equal(first.folderId, folderId);
  assert.equal(first.documentName, 'Xét nghiệm máu');
  assert.equal(first.ciphertextSize, 32);
  assert.equal(first.ciphertextSha256, sha256Hex(ciphertext));
  assert.match(first.objectKey, new RegExp(`^${revisionId}/[0-9a-f-]{36}$`));
  assert.deepEqual([...storage.objects.keys()], [first.objectKey]);

  const conflict = await call(`/documents/${documentId}/versions`, {
    method: 'POST', body: uploadForm({ metadata: { documentName: undefined, category: undefined } }),
  });
  assert.equal(conflict.status, 409);
  assert.deepEqual(await conflict.json(), { code: 'VERSION_CONFLICT', currentVersionId: 'v9' });
  assert.equal(inputs[1].documentId, documentId);
  assert.equal(inputs[1].folderId, undefined);

  const failed = await call(`/folders/${folderId}/documents`, {
    method: 'POST', body: uploadForm({ metadata: { mimeType: 'application/x-explode' } }),
  });
  assert.equal(failed.status, 500);
  assert.deepEqual([...storage.objects.keys()], [first.objectKey]);
});

test('uploads reject malformed, mismatched or oversized ciphertext without storing it', async (t) => {
  const storage = createMemoryStorage();
  let published = 0;
  const call = await startApp(t, {
    objectStorage: storage,
    maxUploadBytes: 64,
    documentRepository: { async publishUpload() { published += 1; return { code: 'FORBIDDEN' }; } },
  });
  const upload = (form) => call(`/folders/${folderId}/documents`, { method: 'POST', body: form });
  const expectations = [
    [uploadForm({ manifest: { ciphertextSha256: '0'.repeat(64) } }), 422, 'CIPHERTEXT_HASH_MISMATCH'],
    [uploadForm({ manifest: { ciphertextSize: 31 } }), 422, 'CIPHERTEXT_HASH_MISMATCH'],
    [uploadForm({ manifest: { revisionId: 'bad' } }), 422, 'MANIFEST_MISMATCH'],
    [uploadForm({ ciphertext: Buffer.alloc(100, 1) }), 413, 'PAYLOAD_TOO_LARGE'],
    [uploadForm({ ciphertext: Buffer.alloc(8, 1) }), 400, 'INVALID_DOCUMENT_INPUT'],
    [uploadForm({ metadata: { category: 'BAD' } }), 400, 'INVALID_DOCUMENT_INPUT'],
    [uploadForm({ metadata: { documentName: '   ' } }), 400, 'INVALID_DOCUMENT_INPUT'],
    [uploadForm({ metadata: { mimeType: 'pdf' } }), 400, 'INVALID_DOCUMENT_INPUT'],
    [uploadForm({ metadata: { contextId: 'x' } }), 400, 'INVALID_DOCUMENT_INPUT'],
  ];
  const onlyFile = new FormData();
  onlyFile.append('ciphertext', new Blob([Buffer.alloc(32)]), 'ciphertext.bin');
  expectations.push([onlyFile, 400, 'INVALID_DOCUMENT_INPUT']);
  const extraField = uploadForm();
  extraField.append('other', 'x');
  expectations.push([extraField, 400, 'INVALID_DOCUMENT_INPUT']);
  for (const [form, status, code] of expectations) {
    const response = await upload(form);
    assert.equal(response.status, status, code);
    assert.deepEqual(await response.json(), { code });
  }
  const json = await call(`/folders/${folderId}/documents`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
  });
  assert.equal(json.status, 400);
  assert.equal(storage.objects.size, 0);
  assert.equal(published, 0);
});

test('downloads return the caller manifest and the active ciphertext revision', async (t) => {
  const storage = createMemoryStorage();
  storage.objects.set('k1', Buffer.from([1, 2, 3]));
  const oldRevision = randomUUID();
  const call = await startApp(t, {
    objectStorage: storage,
    documentRepository: {
      async getVersionManifestForUser(userId, id) {
        return userId === '7' && id === versionId ? { versionId, revisionId } : { code: 'VERSION_NOT_FOUND' };
      },
      async getVersionContentForUser(userId, id, requested) {
        if (requested === oldRevision) return { code: 'REVISION_CHANGED', revisionId };
        return { revisionId, objectKey: 'k1', ciphertextSize: 3 };
      },
    },
  });
  const manifest = await call(`/versions/${versionId}/manifest`);
  assert.equal(manifest.status, 200);
  assert.deepEqual(await manifest.json(), { versionId, revisionId });
  assert.equal((await call(`/versions/${versionId}/manifest`, { user: '8' })).status, 404);
  const content = await call(`/versions/${versionId}/content?revisionId=${revisionId}`);
  assert.equal(content.status, 200);
  assert.equal(content.headers.get('content-type'), 'application/octet-stream');
  assert.equal(content.headers.get('x-crypto-revision-id'), revisionId);
  assert.equal(content.headers.get('cache-control'), 'no-store');
  assert.deepEqual(Buffer.from(await content.arrayBuffer()), Buffer.from([1, 2, 3]));
  const stale = await call(`/versions/${versionId}/content?revisionId=${oldRevision}`);
  assert.equal(stale.status, 409);
  assert.deepEqual(await stale.json(), { code: 'REVISION_CHANGED', revisionId });
  assert.equal((await call(`/versions/${versionId}/content?revisionId=bad`)).status, 400);
  assert.equal((await call('/versions/bad/manifest')).status, 400);
});

test('document details, metadata updates and deletion follow repository results', async (t) => {
  const storage = createMemoryStorage();
  storage.objects.set('a/1', Buffer.from('x'));
  storage.objects.set('b/2', Buffer.from('y'));
  const updates = [];
  const call = await startApp(t, {
    objectStorage: storage,
    documentRepository: {
      async findDocumentForUser(userId) { return userId === '7' ? { documentId, role: 'EDITOR' } : null; },
      async listVersionsForUser(userId) { return userId === '7' ? { versions: [] } : null; },
      async updateDocumentMetadata(userId, id, changes) {
        updates.push(changes);
        return userId === '7' ? { documentId: id, ...changes } : { code: 'FORBIDDEN' };
      },
      async deleteDocument(userId) {
        return userId === '5' ? { objectKeys: ['a/1', 'b/2'] } : { code: 'FORBIDDEN' };
      },
    },
  });
  assert.deepEqual(await (await call(`/documents/${documentId}`)).json(), { documentId, role: 'EDITOR' });
  assert.equal((await call(`/documents/${documentId}`, { user: '8' })).status, 404);
  assert.deepEqual(await (await call(`/documents/${documentId}/versions`)).json(), { versions: [] });
  assert.equal((await call(`/documents/${documentId}/versions`, { user: '8' })).status, 404);
  const patch = (body, user = '7') => call(`/documents/${documentId}`, {
    method: 'PATCH', user, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  const renamed = await patch({ documentName: '  Đơn thuốc  ' });
  assert.equal(renamed.status, 200);
  assert.deepEqual(await renamed.json(), { documentId, documentName: 'Đơn thuốc' });
  assert.equal((await patch({ category: 'PRESCRIPTION' }, '8')).status, 403);
  for (const body of [{}, { folderId }, { category: 'BAD' }, { documentName: '' }, { documentName: 'x'.repeat(256) }]) {
    assert.equal((await patch(body)).status, 400, JSON.stringify(body));
  }
  assert.deepEqual(updates, [{ documentName: 'Đơn thuốc' }, { category: 'PRESCRIPTION' }]);
  assert.equal((await call(`/documents/${documentId}`, { method: 'DELETE', user: '7' })).status, 403);
  assert.equal(storage.objects.size, 2);
  const deleted = await call(`/documents/${documentId}`, { method: 'DELETE', user: '5' });
  assert.equal(deleted.status, 204);
  assert.equal(storage.objects.size, 0);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && node --test test/documents.test.js`
Expected: FAIL. Document routes return 404 from Express (router not mounted yet), for example `expected 401, actual 404`.

- [ ] **Step 3: Implement the router**

`src/documents/document-router.js`:
```js
const { createHash, randomUUID } = require('node:crypto');
const express = require('express');
const multer = require('multer');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CATEGORIES = new Set(['MEDICAL_REPORT', 'LABORATORY_RESULT', 'PRESCRIPTION', 'MEDICAL_IMAGE', 'OTHER']);
const MIME_TYPE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,62}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}$/i;
const GCM_TAG_BYTES = 16;
const DEFAULT_MAX_UPLOAD_BYTES = 25 * 1024 * 1024;
const statusByCode = {
  FORBIDDEN: 403,
  DOCUMENT_NOT_FOUND: 404,
  VERSION_NOT_FOUND: 404,
  FOLDER_NOT_READY: 409,
  CONTEXT_NOT_FOUND: 409,
  CONTEXT_USED: 409,
  CONTEXT_EXPIRED: 409,
  CONTEXT_STALE: 409,
  VERSION_CONFLICT: 409,
  SIGNING_KEY_MISSING: 409,
  RECIPIENT_KEY_MISSING: 409,
  ENVELOPE_NOT_AVAILABLE: 409,
  REVISION_CHANGED: 409,
  INVALID_SIGNATURE: 422,
  MANIFEST_MISMATCH: 422,
  CIPHERTEXT_HASH_MISMATCH: 422,
  RECIPIENTS_MISMATCH: 422,
};

function isUuid(value) {
  return typeof value === 'string' && UUID.test(value);
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function cleanName(value) {
  if (typeof value !== 'string') return null;
  const name = value.trim();
  return name && Array.from(name).length <= 255 ? name : null;
}

function sendResult(response, result, successStatus = 200) {
  if (result.code) {
    const status = statusByCode[result.code];
    if (!status) throw new Error(`Unmapped document result code: ${result.code}`);
    return response.status(status).json(result);
  }
  return response.status(successStatus).json(result);
}

function parseUploadMetadata(raw, purpose) {
  if (typeof raw !== 'string') return null;
  let metadata;
  try {
    metadata = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!isPlainObject(metadata) || !isUuid(metadata.contextId) || !isPlainObject(metadata.manifest)
      || typeof metadata.signature !== 'string' || !Array.isArray(metadata.envelopes)
      || metadata.envelopes.length > 1000 || typeof metadata.mimeType !== 'string'
      || metadata.mimeType.length > 127 || !MIME_TYPE.test(metadata.mimeType)) {
    return null;
  }
  const upload = {
    contextId: metadata.contextId,
    manifest: metadata.manifest,
    signature: metadata.signature,
    envelopes: metadata.envelopes,
    mimeType: metadata.mimeType.toLowerCase(),
  };
  if (purpose === 'NEW_VERSION') return upload;
  const documentName = cleanName(metadata.documentName);
  if (!documentName || !CATEGORIES.has(metadata.category)) return null;
  return { ...upload, documentName, category: metadata.category };
}

function createDocumentRouter({
  authenticate, documentRepository, objectStorage, maxUploadBytes = DEFAULT_MAX_UPLOAD_BYTES,
} = {}) {
  const router = express.Router();

  // Guards run per route, so requests for other /api/v1 modules pass through untouched.
  function requireService(request, response, next) {
    response.set('Cache-Control', 'no-store');
    if (!request.user?.id) return response.status(401).json({ code: 'UNAUTHENTICATED' });
    if (!documentRepository || !objectStorage) {
      return response.status(503).json({ code: 'DOCUMENT_SERVICE_UNAVAILABLE' });
    }
    next();
  }
  const guard = authenticate ? [authenticate, requireService] : [requireService];
  const checkFolderId = (request, response, next) => (
    isUuid(request.params.folderId) ? next() : response.status(403).json({ code: 'FORBIDDEN' }));
  const checkDocumentId = (request, response, next) => (
    isUuid(request.params.documentId) ? next() : response.status(400).json({ code: 'INVALID_DOCUMENT_ID' }));
  const checkVersionId = (request, response, next) => (
    isUuid(request.params.versionId) ? next() : response.status(400).json({ code: 'INVALID_VERSION_ID' }));
  const smallJson = express.json({ limit: '16kb' });

  const parseCiphertext = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: maxUploadBytes, files: 1, fields: 1, parts: 2, fieldSize: 1024 * 1024 },
  }).single('ciphertext');
  function parseMultipart(request, response, next) {
    parseCiphertext(request, response, (error) => {
      if (!error) return next();
      if (error.code === 'LIMIT_FILE_SIZE') return response.status(413).json({ code: 'PAYLOAD_TOO_LARGE' });
      return response.status(400).json({ code: 'INVALID_DOCUMENT_INPUT' });
    });
  }

  async function discardObject(objectKey) {
    try {
      await objectStorage.delete(objectKey);
    } catch (error) {
      console.error(`Could not delete unpublished object ${objectKey}: ${error.code ?? error.message}`);
    }
  }

  function publish(purpose) {
    return async (request, response) => {
      const upload = parseUploadMetadata(request.body?.metadata, purpose);
      const ciphertext = request.file?.buffer;
      if (!upload || !ciphertext || ciphertext.length < GCM_TAG_BYTES) {
        return response.status(400).json({ code: 'INVALID_DOCUMENT_INPUT' });
      }
      const ciphertextSha256 = createHash('sha256').update(ciphertext).digest('hex');
      if (upload.manifest.ciphertextSha256 !== ciphertextSha256 || upload.manifest.ciphertextSize !== ciphertext.length) {
        return response.status(422).json({ code: 'CIPHERTEXT_HASH_MISMATCH' });
      }
      if (!isUuid(upload.manifest.revisionId)) return response.status(422).json({ code: 'MANIFEST_MISMATCH' });
      // A fresh suffix per request: a repeated or concurrent submission never
      // overwrites or deletes another request's object.
      const objectKey = `${upload.manifest.revisionId}/${randomUUID()}`;
      await objectStorage.put(objectKey, ciphertext);
      const scope = purpose === 'NEW_DOCUMENT'
        ? { folderId: request.params.folderId }
        : { documentId: request.params.documentId };
      let result;
      try {
        result = await documentRepository.publishUpload({
          ...upload, ...scope, purpose, userId: request.user.id,
          objectKey, ciphertextSize: ciphertext.length, ciphertextSha256,
        });
      } catch (error) {
        await discardObject(objectKey);
        throw error;
      }
      if (result.code) {
        await discardObject(objectKey);
        return sendResult(response, result);
      }
      response.location('/api/v1/documents/' + result.documentId);
      return sendResult(response, result, 201);
    };
  }
  const uploadDocument = publish('NEW_DOCUMENT');
  const createDocumentVersion = publish('NEW_VERSION');

  router.get('/folders/:folderId/documents', guard, checkFolderId, async function listFolderDocuments(request, response) {
    const { query = '', category, page = '1' } = request.query;
    if (typeof page !== 'string' || !/^[1-9][0-9]{0,8}$/.test(page)) {
      return response.status(400).json({ code: 'INVALID_DOCUMENT_PAGE' });
    }
    if (typeof query !== 'string' || Array.from(query).length > 100
        || (category !== undefined && !CATEGORIES.has(category))) {
      return response.status(400).json({ code: 'INVALID_DOCUMENT_INPUT' });
    }
    const result = await documentRepository.listDocumentsForUser(request.user.id, request.params.folderId, {
      query: query.trim(), category, page: Number(page),
    });
    return sendResult(response, result);
  });

  router.post('/folders/:folderId/upload-contexts', guard, checkFolderId, smallJson, async function createUploadContext(request, response) {
    const body = request.body;
    const keys = isPlainObject(body) ? Object.keys(body) : [];
    const valid = isPlainObject(body) && (
      (body.purpose === 'NEW_DOCUMENT' && keys.length === 1)
      || (body.purpose === 'NEW_VERSION' && keys.length === 3 && isUuid(body.documentId) && isUuid(body.baseVersionId)));
    if (!valid) return response.status(400).json({ code: 'INVALID_UPLOAD_CONTEXT_INPUT' });
    const contextRequest = body.purpose === 'NEW_DOCUMENT'
      ? { purpose: 'NEW_DOCUMENT' }
      : { purpose: 'NEW_VERSION', documentId: body.documentId, baseVersionId: body.baseVersionId };
    const result = await documentRepository.createUploadContext(request.user.id, request.params.folderId, contextRequest);
    return sendResult(response, result, 201);
  });

  router.post('/folders/:folderId/documents', guard, checkFolderId, parseMultipart, uploadDocument);

  router.get('/documents/:documentId', guard, checkDocumentId, async function getDocument(request, response) {
    const document = await documentRepository.findDocumentForUser(request.user.id, request.params.documentId);
    if (!document) return response.status(404).json({ code: 'DOCUMENT_NOT_FOUND' });
    return response.json(document);
  });

  router.patch('/documents/:documentId', guard, checkDocumentId, smallJson, async function updateDocumentMetadata(request, response) {
    const body = request.body;
    const keys = isPlainObject(body) ? Object.keys(body) : [];
    const changes = {};
    let valid = keys.length > 0 && keys.every((key) => key === 'documentName' || key === 'category');
    if (valid && Object.hasOwn(body, 'documentName')) {
      changes.documentName = cleanName(body.documentName);
      valid = Boolean(changes.documentName);
    }
    if (valid && Object.hasOwn(body, 'category')) {
      changes.category = body.category;
      valid = CATEGORIES.has(body.category);
    }
    if (!valid) return response.status(400).json({ code: 'INVALID_DOCUMENT_INPUT' });
    const result = await documentRepository.updateDocumentMetadata(request.user.id, request.params.documentId, changes);
    return sendResult(response, result);
  });

  router.delete('/documents/:documentId', guard, checkDocumentId, async function deleteDocument(request, response) {
    const result = await documentRepository.deleteDocument(request.user.id, request.params.documentId);
    if (result.code) return sendResult(response, result);
    // Rows are gone; ciphertext objects are removed after the commit (best effort).
    for (const objectKey of result.objectKeys) await discardObject(objectKey);
    return response.status(204).end();
  });

  router.get('/documents/:documentId/versions', guard, checkDocumentId, async function listDocumentVersions(request, response) {
    const result = await documentRepository.listVersionsForUser(request.user.id, request.params.documentId);
    if (!result) return response.status(404).json({ code: 'DOCUMENT_NOT_FOUND' });
    return response.json(result);
  });

  router.post('/documents/:documentId/versions', guard, checkDocumentId, parseMultipart, createDocumentVersion);

  router.get('/versions/:versionId/manifest', guard, checkVersionId, async function getVersionManifest(request, response) {
    const result = await documentRepository.getVersionManifestForUser(request.user.id, request.params.versionId);
    return sendResult(response, result);
  });

  router.get('/versions/:versionId/content', guard, checkVersionId, async function downloadVersionCiphertext(request, response) {
    const { revisionId } = request.query;
    if (revisionId !== undefined && !isUuid(revisionId)) {
      return response.status(400).json({ code: 'INVALID_DOCUMENT_INPUT' });
    }
    const result = await documentRepository.getVersionContentForUser(request.user.id, request.params.versionId, revisionId);
    if (result.code) return sendResult(response, result);
    const ciphertext = await objectStorage.get(result.objectKey);
    response.set({ 'Content-Type': 'application/octet-stream', 'X-Crypto-Revision-Id': result.revisionId });
    return response.send(ciphertext);
  });

  return router;
}

module.exports = { createDocumentRouter };
```

- [ ] **Step 4: Wire the router into `src/server.js` (additions only)**

Add two requires after the existing requires:
```js
const { createDocumentRouter } = require('./documents/document-router');
const { createMysqlDocumentRepository } = require('./documents/mysql-document-repository');
```

Extend the `createApp` parameter list by adding one line after `verifyFolderDeletionReauth,`:
```js
  documentRepository, objectStorage, keyDirectory, maxUploadBytes, uploadContextTtlSeconds,
```

Add as the first line inside `createApp`, before `const app = express();`:
```js
  folderPolicyKeys ??= keyDirectory;
```

Add directly before `app.use('/api/v1/folders', createFolderRouter({`:
```js
  const documents = documentRepository ?? (mysqlPool && keyDirectory
    ? createMysqlDocumentRepository(mysqlPool, { keyDirectory, uploadContextTtlSeconds })
    : undefined);
  // Mounted before the folders router: its routes (/folders/:id/documents, ...)
  // would otherwise reach the folders router first.
  app.use('/api/v1', createDocumentRouter({
    authenticate, documentRepository: documents, objectStorage, maxUploadBytes,
  }));
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && npm test`
Expected: PASS, 41 tests (all folders tests still pass).

- [ ] **Step 6: Commit**

```bash
git add backend/src/documents/document-router.js backend/src/server.js backend/test/documents.test.js
git commit -m "Add document management HTTP routes"
```

---
### Task 10: Entry point, dev accounts, rotation unblock tool, seed

**Files:**
- Create: `src/main.js`, `scripts/lib/dev-accounts.cjs`, `scripts/dev-complete-rotations.cjs`, `scripts/seed.cjs`
- Modify: `package.json` (scripts)

**Interfaces:**
- Consumes: everything from Tasks 1–9.
- Produces:
  - `src/main.js`: `createPool(dbConfig)`, `buildApp({ config, pool })`; running it starts the server on `127.0.0.1:<PORT>`.
  - `scripts/lib/dev-accounts.cjs`: `createDevUser(executor, { email, fullName, accountType = 'STAFF', withKeys = true }) → { userId, email, fullName, accountType, keys? }` where `keys = { encryption: { keyId, publicJwk, privateJwk }, signing: { keyId, publicJwk, privateJwk } }`; `signPayload(privateJwk, payload) → base64url`; `writeDevKeyFile(dir, user)`; `createApiClient(baseUrl) → call(path, userId, expectedStatus, { method, body, form, raw, headers })`; `createFolderWithMembers({ call, owner, folder, members }) → folderId`; `addFolderMember({ call, owner, folderId, userId, role })`; `startDevServer({ config, pool }) → { baseUrl, close() }`.
  - `scripts/dev-complete-rotations.cjs`: `completeFolderRotations(executor, folderId) → { completed, documentCount }`.

- [ ] **Step 1: Write `src/main.js`**

```js
const mysql = require('mysql2/promise');
const { devHeaderAuth } = require('./auth/dev-header-auth');
const { loadConfig, loadDotEnv } = require('./config');
const { createMysqlKeyDirectory } = require('./keys/mysql-key-directory');
const { createApp } = require('./server');
const { createLocalObjectStorage } = require('./storage/local-object-storage');

function createPool(db) {
  return mysql.createPool({ ...db, timezone: 'Z', waitForConnections: true, connectionLimit: 10 });
}

function selectAuthentication(config) {
  // Only AUTH_MODE=dev exists today; the Auth module adds its session middleware here.
  if (config.authMode === 'dev') return devHeaderAuth;
  throw new Error(`Unsupported AUTH_MODE: ${config.authMode}`);
}

function buildApp({ config, pool }) {
  return createApp({
    authenticate: selectAuthentication(config),
    mysqlPool: pool,
    keyDirectory: createMysqlKeyDirectory(),
    objectStorage: createLocalObjectStorage({ rootDir: config.storage.dir }),
    maxUploadBytes: config.maxUploadBytes,
    uploadContextTtlSeconds: config.uploadContextTtlSeconds,
  });
}

async function main() {
  loadDotEnv();
  const config = loadConfig();
  const pool = createPool(config.db);
  await pool.query('SELECT 1');
  // Dev header auth trusts any caller, so the dev server only listens on loopback.
  buildApp({ config, pool }).listen(config.port, '127.0.0.1', () => {
    console.log(`Backend running at http://localhost:${config.port}`);
    console.warn('AUTH_MODE=dev: X-Dev-User-Id identifies the caller. Development use only.');
  });
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

module.exports = { buildApp, createPool };
```

- [ ] **Step 2: Write `scripts/lib/dev-accounts.cjs`**

```js
// Development helpers shared by seed.cjs and smoke-documents.cjs. They play the
// browser's role: generate key pairs, sign policies, call the API with X-Dev-User-Id.
const { randomUUID, webcrypto } = require('node:crypto');
const { once } = require('node:events');
const fs = require('node:fs/promises');
const path = require('node:path');
const canonicalize = require('canonicalize');
const { fingerprintPublicJwk, toPublicJwk } = require('../../src/keys/mysql-key-directory');
const { buildApp } = require('../../src/main');

const { subtle } = webcrypto;
const RSA_OAEP = { name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' };
const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' };

async function generateKeyPair(algorithm, usages, purpose) {
  const { publicKey, privateKey } = await subtle.generateKey(algorithm, true, usages);
  return {
    keyId: randomUUID(),
    publicJwk: toPublicJwk(await subtle.exportKey('jwk', publicKey), purpose),
    privateJwk: await subtle.exportKey('jwk', privateKey),
  };
}

async function createDevUser(executor, { email, fullName, accountType = 'STAFF', withKeys = true }) {
  const [result] = await executor.execute(
    'INSERT INTO `User` (email, full_name, account_type) VALUES (?, ?, ?)', [email, fullName, accountType],
  );
  const user = { userId: String(result.insertId), email, fullName, accountType };
  if (!withKeys) return user;
  const keys = {
    encryption: await generateKeyPair(RSA_OAEP, ['encrypt', 'decrypt'], 'ENCRYPTION'),
    signing: await generateKeyPair(ECDSA, ['sign', 'verify'], 'SIGNING'),
  };
  const rows = [
    ['ENCRYPTION', 'RSA-OAEP-3072-SHA256', keys.encryption],
    ['SIGNING', 'ECDSA-P256-SHA256', keys.signing],
  ];
  for (const [purpose, algorithm, key] of rows) {
    await executor.execute(`
      INSERT INTO User_Key (key_id, user_id, purpose, algorithm, public_key_jwk, fingerprint, status, activated_at)
      VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', UTC_TIMESTAMP(3))
    `, [key.keyId, user.userId, purpose, algorithm, JSON.stringify(key.publicJwk), fingerprintPublicJwk(key.publicJwk)]);
  }
  return { ...user, keys };
}

async function signPayload(privateJwk, payload) {
  const key = await subtle.importKey('jwk', privateJwk, ECDSA, false, ['sign']);
  const signature = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, Buffer.from(canonicalize(payload)));
  return Buffer.from(signature).toString('base64url');
}

async function writeDevKeyFile(dir, user) {
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(path.join(dir, `${user.userId}.json`), JSON.stringify(user, null, 2), { mode: 0o600 });
}

function createApiClient(baseUrl) {
  return async function call(urlPath, userId, expectedStatus, { method = 'GET', body, form, raw = false, headers = {} } = {}) {
    const init = { method, headers: { 'x-dev-user-id': userId, ...headers } };
    if (form) init.body = form;
    else if (body !== undefined) {
      init.headers['content-type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    const response = await fetch(baseUrl + urlPath, init);
    const bytes = Buffer.from(await response.arrayBuffer());
    let data = bytes;
    if (!raw && bytes.length) {
      try {
        data = JSON.parse(bytes.toString('utf8'));
      } catch {
        data = bytes;
      }
    }
    if (response.status !== expectedStatus) {
      const detail = Buffer.isBuffer(data) ? data.toString('utf8') : JSON.stringify(data);
      throw new Error(`${method} ${urlPath}: expected ${expectedStatus}, got ${response.status} ${detail}`);
    }
    return raw ? { data, headers: response.headers } : data;
  };
}

async function addFolderMember({ call, owner, folderId, userId, role }) {
  const context = await call(`/folders/${folderId}/policy-contexts`, owner.userId, 201, {
    method: 'POST', body: { action: 'ADD_MEMBER', userId, role },
  });
  const ownerSignature = await signPayload(owner.keys.signing.privateJwk, { purpose: 'FOLDER_MEMBERSHIP_CHANGE', context });
  return call(`/folders/${folderId}/members`, owner.userId, 202, {
    method: 'POST', body: { policyContextId: context.contextId, ownerSignature },
  });
}

async function createFolderWithMembers({ call, owner, folder, members = [] }) {
  const folderId = randomUUID();
  const payload = {
    purpose: 'INITIAL_FOLDER_POLICY',
    folder: { folderId, ...folder },
    ownerId: owner.userId,
    policyVersion: 1,
    members: [{ userId: owner.userId, role: 'OWNER' }],
  };
  await call('/folders', owner.userId, 201, {
    method: 'POST',
    body: { folderId, ...folder, signedPolicy: { payload, signature: await signPayload(owner.keys.signing.privateJwk, payload) } },
  });
  for (const { user, role } of members) {
    await addFolderMember({ call, owner, folderId, userId: user.userId, role });
  }
  return folderId;
}

async function startDevServer({ config, pool }) {
  const server = buildApp({ config, pool }).listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {
    baseUrl: `http://127.0.0.1:${server.address().port}/api/v1`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

module.exports = {
  addFolderMember, createApiClient, createDevUser, createFolderWithMembers, signPayload, startDevServer, writeDevKeyFile,
};
```

- [ ] **Step 3: Write `scripts/dev-complete-rotations.cjs`**

```js
// DEVELOPMENT ONLY. Rotation commit (commitRotation) is not implemented yet, so a
// folder stays FOLDER_NOT_READY after any membership change. This marks the
// folder's unfinished rotation jobs COMPLETED so local testing can continue.
// It does not re-encrypt anything: new members get no envelopes for existing
// documents and DEKs are not rotated. Remove once rotation commit exists.
const { loadConfig, loadDotEnv } = require('../src/config');
const { createPool } = require('../src/main');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

async function completeFolderRotations(executor, folderId) {
  const [result] = await executor.execute(`
    UPDATE Folder_Rotation_Job SET status = 'COMPLETED', finished_at = UTC_TIMESTAMP(3)
    WHERE folder_id = ?
      AND status IN ('PENDING', 'IN_PROGRESS', 'WAITING_FOR_CLIENT', 'WAITING_FOR_KEY', 'WAITING_FOR_OWNER')
  `, [folderId]);
  const [[documents]] = await executor.execute('SELECT COUNT(*) AS count FROM Document WHERE folder_id = ?', [folderId]);
  return { completed: result.affectedRows, documentCount: Number(documents.count) };
}

async function main() {
  const folderId = process.argv[2];
  if (!UUID.test(folderId ?? '')) {
    throw new Error('Usage: npm run dev:complete-rotations -- <folderId>');
  }
  loadDotEnv();
  const config = loadConfig();
  if (config.nodeEnv === 'production') throw new Error('dev:complete-rotations is not allowed in production');
  const pool = createPool(config.db);
  try {
    const { completed, documentCount } = await completeFolderRotations(pool, folderId);
    console.log(`Marked ${completed} rotation job(s) COMPLETED for folder ${folderId}`);
    if (documentCount > 0) {
      console.warn(`Warning: the folder has ${documentCount} document(s). Members added since the last upload have no envelope (ENVELOPE_NOT_AVAILABLE) and DEKs were not rotated.`);
    }
  } finally {
    await pool.end();
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

module.exports = { completeFolderRotations };
```

- [ ] **Step 4: Write `scripts/seed.cjs`**

```js
// DEVELOPMENT ONLY. Creates 1 admin + 15 staff accounts with ACTIVE key pairs and
// three demo treatment folders. Private keys are written to data/dev-keys/<userId>.json
// (gitignored) so the smoke test and frontend developers can act as these users.
const path = require('node:path');
const { backendDir, loadConfig, loadDotEnv } = require('../src/config');
const { createPool } = require('../src/main');
const {
  createApiClient, createDevUser, createFolderWithMembers, startDevServer, writeDevKeyFile,
} = require('./lib/dev-accounts.cjs');
const { completeFolderRotations } = require('./dev-complete-rotations.cjs');

const DEV_KEYS_DIR = path.join(backendDir, 'data', 'dev-keys');

async function main() {
  loadDotEnv();
  const config = loadConfig();
  if (config.nodeEnv === 'production') throw new Error('seed is not allowed in production');
  const pool = createPool(config.db);
  let server;
  try {
    const [[existing]] = await pool.execute("SELECT COUNT(*) AS count FROM `User` WHERE email = 'admin@medshare.test'");
    if (Number(existing.count) > 0) {
      throw new Error('Seed data already exists. Reset with: docker compose down -v && docker compose up -d --wait && npm run migrate && npm run seed');
    }
    const admin = await createDevUser(pool, {
      email: 'admin@medshare.test', fullName: 'Quản trị viên bệnh viện', accountType: 'ADMIN', withKeys: false,
    });
    const staff = [];
    for (let index = 1; index <= 15; index += 1) {
      const number = String(index).padStart(2, '0');
      const user = await createDevUser(pool, { email: `staff${number}@medshare.test`, fullName: `Nhân viên ${number}` });
      await writeDevKeyFile(DEV_KEYS_DIR, user);
      staff.push(user);
    }
    server = await startDevServer({ config, pool });
    const call = createApiClient(server.baseUrl);
    const s = (number) => staff[number - 1];
    const folders = [
      {
        owner: s(1),
        folder: { name: 'Điều trị nội khoa - BN001', patientRef: 'DEMO-PATIENT-001', treatmentReference: 'DEMO-EPISODE-001' },
        members: [{ user: s(2), role: 'EDITOR' }, { user: s(3), role: 'EDITOR' }, { user: s(4), role: 'VIEWER' }, { user: s(5), role: 'VIEWER' }],
      },
      {
        owner: s(2),
        folder: { name: 'Xét nghiệm - BN002', patientRef: 'DEMO-PATIENT-002', treatmentReference: 'DEMO-EPISODE-002' },
        members: [{ user: s(6), role: 'EDITOR' }, { user: s(1), role: 'VIEWER' }, { user: s(7), role: 'VIEWER' }],
      },
      {
        owner: s(8),
        folder: { name: 'Chẩn đoán hình ảnh - BN003', patientRef: 'DEMO-PATIENT-003', treatmentReference: 'DEMO-EPISODE-003' },
        members: [{ user: s(9), role: 'EDITOR' }, { user: s(10), role: 'VIEWER' }],
      },
    ];
    const roles = new Map(staff.map((user) => [user.userId, []]));
    for (const entry of folders) {
      const folderId = await createFolderWithMembers({ call, ...entry });
      await completeFolderRotations(pool, folderId);
      roles.get(entry.owner.userId).push(`OWNER ${entry.folder.name} (${folderId})`);
      for (const { user, role } of entry.members) roles.get(user.userId).push(`${role} ${entry.folder.name}`);
    }
    console.log(`ADMIN  user ${admin.userId}  ${admin.email}`);
    for (const user of staff) {
      console.log(`STAFF  user ${user.userId}  ${user.email}  ${roles.get(user.userId).join('; ') || 'no folder (outsider)'}`);
    }
    console.log(`Private keys for staff accounts: ${DEV_KEYS_DIR}`);
  } finally {
    if (server) await server.close();
    await pool.end();
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
```

- [ ] **Step 5: Update `package.json` scripts**

The `scripts` object becomes:
```json
{
  "test": "node --test",
  "start": "node src/main.js",
  "migrate": "node scripts/migrate.cjs",
  "seed": "node scripts/seed.cjs",
  "dev:complete-rotations": "node scripts/dev-complete-rotations.cjs",
  "smoke:documents": "node scripts/smoke-documents.cjs"
}
```

- [ ] **Step 6: Verify end-to-end start**

Run:
```bash
cd backend
npm test
npm run seed
(npm start > /tmp/medshare-start.log 2>&1 &) ; sleep 2
curl -s http://127.0.0.1:3000/health/live
curl -s -H 'X-Dev-User-Id: 2' http://127.0.0.1:3000/api/v1/folders
curl -s -H 'X-Dev-User-Id: 2' http://127.0.0.1:3000/api/v1/dashboard/summary
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000/api/v1/folders
pkill -f 'node src/main.js'
```
Expected: `npm test` PASS (41). Seed prints 1 ADMIN line, 15 STAFF lines (staff11–15 "no folder (outsider)") and the key directory path. `/health/live` → `{"status":"ok"}`. User 2 is `staff01` (admin is user 1): folders lists two folders (OWNER of BN001, VIEWER of BN002); dashboard shows `folderCount: 2, documentCount: 0`. The request without header prints `401`.

- [ ] **Step 7: Commit**

```bash
git add backend/src/main.js backend/scripts/lib/dev-accounts.cjs backend/scripts/dev-complete-rotations.cjs backend/scripts/seed.cjs backend/package.json
git commit -m "Add backend entry point, dev seed accounts and rotation unblock tool"
```

---

### Task 11: End-to-end smoke test, backend README, notes

**Files:**
- Create: `scripts/lib/dev-document-client.cjs`, `scripts/smoke-documents.cjs`, `README.md` (inside `backend/`)
- Modify: `takenote.md` (repo root) only if implementation revealed a new deviation

**Interfaces:**
- Consumes: `scripts/lib/dev-accounts.cjs`, `completeFolderRotations` (Task 10).
- Produces: `prepareUpload({ context, author, plaintext, documentName, category, mimeType }) → { form, ciphertext, manifest }`; `downloadAndDecrypt({ call, user, versionId }) → Buffer`; `npm run smoke:documents`.

- [ ] **Step 1: Write `scripts/lib/dev-document-client.cjs`**

```js
// Plays the browser for documents: AES-256-GCM encryption, RSA-OAEP DEK envelopes,
// ECDSA-signed CryptoManifest (spec 7.4), and the reverse path for downloads.
const assert = require('node:assert/strict');
const { createHash, webcrypto } = require('node:crypto');
const canonicalize = require('canonicalize');
const { signPayload } = require('./dev-accounts.cjs');

const { subtle } = webcrypto;
const RSA_OAEP = { name: 'RSA-OAEP', hash: 'SHA-256' };

function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

function aadFor({ folderId, documentId, versionId, revisionId }) {
  return Buffer.from(canonicalize({ purpose: 'DOCUMENT_VERSION_UPLOAD', folderId, documentId, versionId, revisionId }));
}

function oaepLabelFor({ folderId, documentId, versionId, revisionId }, recipientKeyId) {
  return Buffer.from(canonicalize({ purpose: 'DEK_ENVELOPE', folderId, documentId, versionId, revisionId, recipientKeyId }));
}

async function prepareUpload({ context, author, plaintext, documentName, category, mimeType }) {
  const dek = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const nonce = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertext = Buffer.from(await subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aadFor(context), tagLength: 128 }, dek, plaintext,
  ));
  const rawDek = await subtle.exportKey('raw', dek);
  const envelopes = [];
  for (const recipient of context.recipients) {
    const publicKey = await subtle.importKey('jwk', recipient.publicKeyJwk, RSA_OAEP, false, ['encrypt']);
    const wrapped = await subtle.encrypt({ name: 'RSA-OAEP', label: oaepLabelFor(context, recipient.keyId) }, publicKey, rawDek);
    envelopes.push({ userId: recipient.userId, keyId: recipient.keyId, wrappedDek: Buffer.from(wrapped).toString('base64url') });
  }
  // In the real client the AuthorRecord travels inside the encrypted container.
  const authorRecord = {
    documentId: context.documentId, versionId: context.versionId, baseVersionId: context.baseVersionId,
    authorUserId: author.userId, authorKeyId: author.keys.signing.keyId,
    policyVersion: context.policyVersion, plaintextSha256: sha256Hex(plaintext),
  };
  const manifest = {
    purpose: 'DOCUMENT_VERSION_UPLOAD',
    contextId: context.contextId,
    folderId: context.folderId,
    documentId: context.documentId,
    versionId: context.versionId,
    revisionId: context.revisionId,
    versionNumber: context.versionNumber,
    baseVersionId: context.baseVersionId,
    policyVersion: context.policyVersion,
    actorUserId: author.userId,
    signerKeyId: context.signerKeyId,
    aead: { alg: 'AES-256-GCM', nonce: Buffer.from(nonce).toString('base64url') },
    ciphertextSha256: sha256Hex(ciphertext),
    ciphertextSize: ciphertext.length,
    authorRecordSha256: sha256Hex(canonicalize(authorRecord)),
    recipients: envelopes.map(({ userId, keyId, wrappedDek }) => ({
      userId, keyId, wrappedDekSha256: sha256Hex(Buffer.from(wrappedDek, 'base64url')),
    })),
  };
  const signature = await signPayload(author.keys.signing.privateJwk, manifest);
  const form = new FormData();
  form.append('metadata', JSON.stringify({ contextId: context.contextId, documentName, category, mimeType, manifest, signature, envelopes }));
  form.append('ciphertext', new Blob([ciphertext]), 'ciphertext.bin');
  return { form, ciphertext, manifest };
}

async function downloadAndDecrypt({ call, user, versionId }) {
  const evidence = await call(`/versions/${versionId}/manifest`, user.userId, 200);
  const signerKey = await subtle.importKey('jwk', evidence.signer.publicKeyJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const validSignature = await subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' }, signerKey,
    Buffer.from(evidence.signature, 'base64url'), Buffer.from(canonicalize(evidence.manifest)),
  );
  assert.equal(validSignature, true, 'manifest signature verifies');
  const privateKey = await subtle.importKey('jwk', user.keys.encryption.privateJwk, RSA_OAEP, false, ['decrypt']);
  const rawDek = await subtle.decrypt(
    { name: 'RSA-OAEP', label: oaepLabelFor(evidence.manifest, evidence.envelope.keyId) },
    privateKey, Buffer.from(evidence.envelope.wrappedDek, 'base64url'),
  );
  const dek = await subtle.importKey('raw', rawDek, 'AES-GCM', false, ['decrypt']);
  const { data } = await call(`/versions/${versionId}/content?revisionId=${evidence.revisionId}`, user.userId, 200, { raw: true });
  assert.equal(sha256Hex(data), evidence.manifest.ciphertextSha256, 'ciphertext hash matches the manifest');
  return Buffer.from(await subtle.decrypt({
    name: 'AES-GCM', iv: Buffer.from(evidence.manifest.aead.nonce, 'base64url'),
    additionalData: aadFor(evidence.manifest), tagLength: 128,
  }, dek, data));
}

module.exports = { downloadAndDecrypt, prepareUpload };
```

- [ ] **Step 2: Write `scripts/smoke-documents.cjs`**

```js
// End-to-end check of Document Management against the dev MySQL and local storage.
// Requires: docker compose up -d --wait && npm run migrate. Creates its own users.
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { loadConfig, loadDotEnv } = require('../src/config');
const { createPool } = require('../src/main');
const {
  addFolderMember, createApiClient, createDevUser, createFolderWithMembers, startDevServer,
} = require('./lib/dev-accounts.cjs');
const { downloadAndDecrypt, prepareUpload } = require('./lib/dev-document-client.cjs');
const { completeFolderRotations } = require('./dev-complete-rotations.cjs');

async function main() {
  loadDotEnv();
  const config = loadConfig();
  if (config.nodeEnv === 'production') throw new Error('smoke:documents is not allowed in production');
  const pool = createPool(config.db);
  let server;
  try {
    const suffix = randomUUID().slice(0, 8);
    const user = (role) => createDevUser(pool, { email: `smoke-${role}-${suffix}@medshare.test`, fullName: `Smoke ${role}` });
    const [owner, editor, viewer, outsider, late] = [
      await user('owner'), await user('editor'), await user('viewer'), await user('outsider'), await user('late'),
    ];
    server = await startDevServer({ config, pool });
    const call = createApiClient(server.baseUrl);
    const folderId = await createFolderWithMembers({
      call, owner,
      folder: { name: 'Documents smoke test', patientRef: 'SMOKE-PATIENT', treatmentReference: `SMOKE-${suffix}` },
      members: [{ user: editor, role: 'EDITOR' }, { user: viewer, role: 'VIEWER' }],
    });
    const contextsPath = `/folders/${folderId}/upload-contexts`;
    const newDocument = { method: 'POST', body: { purpose: 'NEW_DOCUMENT' } };

    // Membership changes queue rotation jobs; until they finish the folder is not ready.
    assert.equal((await call(contextsPath, owner.userId, 409, newDocument)).code, 'FOLDER_NOT_READY');
    await completeFolderRotations(pool, folderId);
    const dashboardBefore = await call('/dashboard/summary', owner.userId, 200);

    // 1. Owner uploads V1 for every current member.
    const context = await call(contextsPath, owner.userId, 201, newDocument);
    assert.deepEqual(context.recipients.map(({ userId }) => userId).sort(), [owner, editor, viewer].map(({ userId }) => userId).sort());
    const v1Plain = Buffer.from('Kết quả xét nghiệm máu - bản 1');
    const v1Upload = await prepareUpload({
      context, author: owner, plaintext: v1Plain,
      documentName: 'Xét nghiệm máu', category: 'LABORATORY_RESULT', mimeType: 'text/plain',
    });
    const v1 = await call(`/folders/${folderId}/documents`, owner.userId, 201, { method: 'POST', form: v1Upload.form });
    const reused = await prepareUpload({
      context, author: owner, plaintext: v1Plain, documentName: 'Lần 2', category: 'OTHER', mimeType: 'text/plain',
    });
    assert.equal((await call(`/folders/${folderId}/documents`, owner.userId, 409, { method: 'POST', form: reused.form })).code, 'CONTEXT_USED');

    // 2. Viewer decrypts V1.
    assert.deepEqual(await downloadAndDecrypt({ call, user: viewer, versionId: v1.versionId }), v1Plain);

    // 3. Editor creates V2; an upload based on the old V1 conflicts.
    const versionRequest = { method: 'POST', body: { purpose: 'NEW_VERSION', documentId: v1.documentId, baseVersionId: v1.versionId } };
    const editorContext = await call(contextsPath, editor.userId, 201, versionRequest);
    const staleContext = await call(contextsPath, owner.userId, 201, versionRequest);
    const v2Plain = Buffer.from('Kết quả xét nghiệm máu - bản 2');
    const v2Upload = await prepareUpload({ context: editorContext, author: editor, plaintext: v2Plain, mimeType: 'text/plain' });
    const v2 = await call(`/documents/${v1.documentId}/versions`, editor.userId, 201, { method: 'POST', form: v2Upload.form });
    assert.equal(v2.versionNumber, 2);
    const staleUpload = await prepareUpload({ context: staleContext, author: owner, plaintext: Buffer.from('stale'), mimeType: 'text/plain' });
    assert.equal((await call(`/documents/${v1.documentId}/versions`, owner.userId, 409, { method: 'POST', form: staleUpload.form })).code, 'VERSION_CONFLICT');
    const { versions } = await call(`/documents/${v1.documentId}/versions`, viewer.userId, 200);
    assert.deepEqual(versions.map(({ versionNumber, isCurrent }) => [versionNumber, isCurrent]), [[2, true], [1, false]]);
    assert.deepEqual(await downloadAndDecrypt({ call, user: viewer, versionId: v2.versionId }), v2Plain);
    assert.deepEqual(await downloadAndDecrypt({ call, user: viewer, versionId: v1.versionId }), v1Plain);

    // 4. Role checks.
    assert.equal((await call(contextsPath, viewer.userId, 403, newDocument)).code, 'FORBIDDEN');
    assert.equal((await call(`/documents/${v1.documentId}`, outsider.userId, 404)).code, 'DOCUMENT_NOT_FOUND');
    assert.equal((await call(`/documents/${v1.documentId}`, editor.userId, 403, { method: 'DELETE' })).code, 'FORBIDDEN');
    const dashboardAfter = await call('/dashboard/summary', owner.userId, 200);
    assert.equal(dashboardAfter.documentCount, dashboardBefore.documentCount + 1);

    // 5. A new member waits for rotation and then has no envelope for existing documents.
    await addFolderMember({ call, owner, folderId, userId: late.userId, role: 'VIEWER' });
    assert.equal((await call(`/versions/${v2.versionId}/manifest`, viewer.userId, 409)).code, 'FOLDER_NOT_READY');
    await completeFolderRotations(pool, folderId);
    assert.equal((await call(`/versions/${v2.versionId}/manifest`, late.userId, 409)).code, 'ENVELOPE_NOT_AVAILABLE');

    // 6. Owner deletes the document; rows and ciphertext objects disappear.
    const [objects] = await pool.execute(`
      SELECT r.storage_object_key AS objectKey FROM Crypto_Revision AS r
      INNER JOIN Document_Version AS v ON v.version_id = r.version_id WHERE v.document_id = ?
    `, [v1.documentId]);
    assert.equal(objects.length, 2);
    await call(`/documents/${v1.documentId}`, owner.userId, 204, { method: 'DELETE' });
    await call(`/documents/${v1.documentId}`, owner.userId, 404);
    for (const { objectKey } of objects) {
      await assert.rejects(fs.access(path.join(config.storage.dir, ...objectKey.split('/'))), { code: 'ENOENT' });
    }
    const dashboardFinal = await call('/dashboard/summary', owner.userId, 200);
    assert.equal(dashboardFinal.documentCount, dashboardBefore.documentCount);
    console.log('PASS: upload, versions, conflict, download/decrypt, roles, rotation gate and delete on MySQL');
  } finally {
    if (server) await server.close();
    await pool.end();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
```

- [ ] **Step 3: Run the smoke test**

Run: `cd backend && npm run smoke:documents`
Expected: last line `PASS: upload, versions, conflict, download/decrypt, roles, rotation gate and delete on MySQL`, exit code 0.

- [ ] **Step 4: Write `backend/README.md`**

```markdown
# Backend

Express 5 + MySQL 8. Run every command below from `backend/`.

## Chạy local lần đầu

1. `npm install`
2. `cp .env.example .env`, rồi đổi `DB_PASSWORD` và `DB_ROOT_PASSWORD` (chỉ dùng trên máy mình).
3. `docker compose up -d --wait`: chạy MySQL 8 (chỉ mở ở `127.0.0.1:3306`).
4. `npm run migrate`: tạo bảng.
5. `npm run seed`: tạo 1 admin và 15 staff có sẵn key, cùng 3 folder mẫu. Private key của staff nằm ở `data/dev-keys/`.
6. `npm start`: backend chạy ở `http://localhost:3000`.

## Gọi API khi dev

`AUTH_MODE=dev`: backend coi header `X-Dev-User-Id` là người đang đăng nhập.

    curl -H 'X-Dev-User-Id: 2' http://localhost:3000/api/v1/folders

Chế độ này bị chặn khi `NODE_ENV=production`, và server dev chỉ lắng nghe trên `127.0.0.1`. Khi module Auth xong, middleware session thay cho header này (xem `src/main.js`).

Ciphertext lưu trong `data/objects/` (`STORAGE_DRIVER=local`). Bản S3 sẽ làm sau.

## Lệnh

| Lệnh | Việc |
|---|---|
| `npm test` | Unit/router test, không cần MySQL |
| `npm run migrate` | Chạy các migration chưa chạy (ghi vào `schema_migrations`) |
| `npm run seed` | Tạo dữ liệu dev (chỉ chạy một lần trên DB trống) |
| `npm run smoke:documents` | Kiểm tra end-to-end Document Management trên MySQL |
| `npm run dev:complete-rotations -- <folderId>` | **Chỉ dev.** Đánh dấu rotation job của folder là `COMPLETED`, vì rotation commit chưa có. Không mã hóa lại gì |

## Làm lại DB từ đầu

    docker compose down -v && docker compose up -d --wait && npm run migrate && npm run seed

MySQL không rollback được DDL: nếu một migration lỗi giữa chừng, sửa file rồi làm lại DB như trên.

## Tài liệu

- Thiết kế Document Management: `../docs/superpowers/specs/2026-11-23-document-management-design.md`
- Các điểm khác ERD và cần nhóm chốt: `../takenote.md`
```

- [ ] **Step 5: Final verification**

Run:
```bash
cd backend
npm test
npm run smoke:documents
git status --short
```
Expected: `npm test` PASS (41 tests, 0 failures). Smoke prints `PASS`. `git status` shows only the new files of this task. Do not run or change `scripts/smoke-folder-membership.cjs`: it belongs to the folders team and targets a separate `medshare_smoke` database.

If the implementation had to deviate from the spec or ERD in a way not yet listed in `takenote.md`, add a row to the matching section of `takenote.md` now.

- [ ] **Step 6: Commit**

```bash
git add backend/scripts/lib/dev-document-client.cjs backend/scripts/smoke-documents.cjs backend/README.md takenote.md
git commit -m "Add end-to-end document smoke test and backend README"
```

---

## Spec coverage check

| Spec section | Task |
|---|---|
| 2 Isolation rules | Global Constraints, Task 9 Step 4 |
| 3 Units | Tasks 1, 3, 4, 5, 6–9, 10 |
| 4 Config | Task 1 |
| 5 Schema | Task 2 |
| 6 Common rules (identity, roles, readiness, 404/403, no-store, IDs) | Tasks 6–9 |
| 7.1 list | Tasks 6, 9 |
| 7.2 upload context | Tasks 7, 9 |
| 7.3 / 7.9 upload and new version | Tasks 5, 7, 9 |
| 7.4 manifest, AAD, OAEP label | Tasks 5, 11 (client helper) |
| 7.5 / 7.6 / 7.7 / 7.8 get, patch, delete, versions | Tasks 6, 8, 9 |
| 7.10 / 7.11 manifest and content | Tasks 6, 9 |
| 8 Error codes | Task 9 `statusByCode` |
| 9 Dev tools | Tasks 2, 10, 11 |
| 10 Tests | Tasks 1–11 |
