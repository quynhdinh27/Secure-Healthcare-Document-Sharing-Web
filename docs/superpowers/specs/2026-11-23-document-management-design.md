# Document Management (backend) — Design

- Ngày: 2026-11-23
- Phạm vi: nhóm API `documents` / `versions` trong `API_AND_FUNCTION_NAMES (3).md` mục 3, chạy được end-to-end trên máy dev.
- Branch: `feature/document-management`
- Các điểm lệch khỏi ERD và các tài liệu khác được ghi trong `takenote.md` ở thư mục gốc repo.

## 1. Mục tiêu và ngoài phạm vi

### Mục tiêu
1. Triển khai 10 endpoint của API list mục 3:
   - `listFolderDocuments`, `createUploadContext`, `uploadDocument`, `getDocument`
   - `updateDocumentMetadata`, `deleteDocument`, `listDocumentVersions`
   - `createDocumentVersion`, `getVersionManifest`, `downloadVersionCiphertext`
2. Chạy được end-to-end trên máy dev:
   - MySQL 8 qua Docker Compose.
   - Ciphertext lưu ở thư mục local (`STORAGE_DRIVER=local`).
   - Auth giả lập qua header, chỉ dùng khi dev.
   - `npm start` nối với MySQL thật, nên cả các API folders đã có cũng chạy được.
3. Có migration runner, các migration cần thiết và seed 10–20 tài khoản test.

### Ngoài phạm vi (làm sau hoặc thuộc người khác)
- Storage driver `s3` và deploy lên AWS. Phần này thuộc sub-project Deploy, làm sau khi nhóm có tài khoản AWS.
- Login và session thật (Auth), các endpoint đăng ký và kích hoạt key (Key Mgmt), rotation items, commit và retry (Rotation).
- Ghi `Audit_Log`. Code chừa sẵn chỗ để gọi sau.
- Dọn tài liệu khi xóa folder. Việc này thuộc code folders, xem takenote.

### Thứ tự ưu tiên khi tài liệu mâu thuẫn
API list (17/11) > System design > FRS / BRD / Use cases > ERD.

## 2. Nguyên tắc không đụng phần người khác

- Không sửa `src/folders/*`, migration `001`–`008`, test của folders hay `scripts/smoke-folder-membership.cjs`.
- `src/server.js` chỉ được **thêm** code:
  - `createApp` nhận thêm `documentRepository`, `objectStorage`, `keyDirectory`, `maxUploadBytes`.
  - Gắn router Documents.
  - Nếu có `keyDirectory` thì dùng nó làm `folderPolicyKeys` mặc định.
  - Khối `require.main === module` giữ nguyên.
- Phần khởi động thật đặt ở file mới `src/main.js`. `npm start` đổi sang `node src/main.js`.
- `package.json` chỉ thêm, không xóa: dependency `mysql2`, `multer` và các script mới.
- Documents chỉ **đọc** các bảng của folders: `Treatment_Folder`, `Folder_Membership`, `Folder_Policy`, `Folder_Rotation_Job`, `Folder_Deletion_Operation`.
- Bảng `User` và `User_Key` chỉ ở dạng tối thiểu, có comment ghi rõ ai sẽ mở rộng. Người mở rộng dùng `ALTER TABLE` trong migration mới.

## 3. Kiến trúc và file

```
backend/
├─ docker-compose.yml            MySQL 8.0, port 3306, volume medshare-mysql
├─ .env.example
├─ migrations/
│   ├─ 000_create_user.sql
│   ├─ 009_create_user_key.sql
│   ├─ 010_create_document.sql
│   ├─ 011_create_document_version.sql
│   ├─ 012_create_crypto_revision.sql
│   ├─ 013_create_dek_envelope.sql
│   └─ 014_create_upload_context.sql
├─ scripts/
│   ├─ migrate.cjs
│   ├─ seed.cjs
│   ├─ dev-complete-rotations.cjs
│   └─ smoke-documents.cjs
└─ src/
    ├─ main.js
    ├─ config.js
    ├─ auth/dev-header-auth.js
    ├─ storage/local-object-storage.js
    ├─ keys/mysql-key-directory.js
    └─ documents/
        ├─ document-router.js
        ├─ mysql-document-repository.js
        └─ document-manifest.js
```

### Trách nhiệm từng unit

| Unit | Làm gì | Phụ thuộc |
|---|---|---|
| `config.js` | Đọc và kiểm tra env, trả object config đóng băng. Ném lỗi nếu thiếu biến, hoặc nếu `AUTH_MODE=dev` khi `NODE_ENV=production`. | `process.env` |
| `auth/dev-header-auth.js` | Đọc `X-Dev-User-Id` (chuỗi số từ 1 đến 20 chữ số), gán `request.user = { id }`. Không kiểm tra thêm gì, vì router tự trả 401 khi thiếu user. | không |
| `storage/local-object-storage.js` | `put(key, buffer)`, `get(key) → Buffer`, `delete(key)`. Key phải khớp `^[0-9a-f-]{36}/[0-9a-f-]{36}$`. Ghi file tạm rồi `rename` để tránh file ghi dở. `delete` thành công cả khi file không tồn tại. | `node:fs` |
| `keys/mysql-key-directory.js` | `lookupActiveSigningKey(conn, userId) → JWK \| null`, `canReceiveFolderKeys(conn, userId) → bool`, `getActiveSigningKey(conn, userId) → { keyId, publicKeyJwk } \| null`, `getSigningKeyById(conn, keyId)`. Hai hàm đầu có cùng chữ ký mà `createFolderPolicyVerifiers` đang dùng. | MySQL |
| `documents/document-manifest.js` | Hàm thuần, không đụng DB: `buildExpectedManifest(context, upload)`, `verifyManifestSignature(jwk, manifest, signature)` (JCS + ECDSA P-256 + IEEE-P1363 base64url), `checkEnvelopes(context.recipients, envelopes, manifest.recipients)`. | `canonicalize`, `node:crypto` |
| `documents/document-router.js` | Validate input, parse multipart bằng `multer` (lưu trong bộ nhớ, có giới hạn kích thước), tính SHA-256 ciphertext, gọi repository, map `{ code }` sang HTTP. Không chạm DB. | repository, storage |
| `documents/mysql-document-repository.js` | Mọi truy vấn và transaction. Kiểm tra lại membership, role và trạng thái folder ngay trong transaction ghi, khóa theo thứ tự `Treatment_Folder` trước rồi mới tới các dòng khác. | MySQL pool, keyDirectory, manifest |
| `main.js` | Đọc config, tạo pool, chọn auth và storage, gọi `createApp`, rồi listen. | tất cả |

## 4. Cấu hình (`.env.example`)

| Biến | Mặc định | Ghi chú |
|---|---|---|
| `NODE_ENV` | `development` | |
| `PORT` | `3000` | |
| `DB_HOST` / `DB_PORT` / `DB_USER` / `DB_PASSWORD` / `DB_NAME` | `127.0.0.1` / `3306` / `medshare` / *(bắt buộc)* / `medshare` | Khớp với `docker-compose.yml` |
| `AUTH_MODE` | `dev` | Hiện chỉ hỗ trợ `dev`. Khi có Auth thật sẽ thêm `session`. |
| `STORAGE_DRIVER` | `local` | Hiện chỉ hỗ trợ `local`. Bản `s3` làm sau. |
| `STORAGE_DIR` | `./data/objects` | Đã được gitignore |
| `MAX_UPLOAD_MB` | `25` | |
| `UPLOAD_CONTEXT_TTL_SECONDS` | `600` | |

Credentials không bao giờ được ghi vào code. File `.env` đã có trong `.gitignore`. Mật khẩu MySQL trong `docker-compose.yml` lấy từ `.env`.

## 5. Schema

Quy ước:
- ID của tài liệu, version, revision và context là `CHAR(36) CHARACTER SET ascii COLLATE ascii_bin`, giống `folder_id`.
- `user_id` là `BIGINT UNSIGNED`.
- Bảng dùng InnoDB, `utf8mb4`.
- Không dùng `ON DELETE CASCADE`. Xóa tường minh trong transaction, giống code folders.

### 000 `User` (tối thiểu, người làm Auth mở rộng)
| Cột | Kiểu |
|---|---|
| `user_id` | BIGINT UNSIGNED AUTO_INCREMENT PK |
| `email` | VARCHAR(255) NULL UNIQUE |
| `full_name` | VARCHAR(255) NULL |
| `account_type` | ENUM('STAFF','ADMIN') NOT NULL DEFAULT 'STAFF' |
| `account_status` | ENUM('ACTIVE','DISABLED') NOT NULL DEFAULT 'ACTIVE' |
| `created_at`, `updated_at` | TIMESTAMP |

`email` và `full_name` cho phép NULL vì `smoke-folder-membership.cjs` chỉ insert `user_id`.

### 009 `User_Key` (tối thiểu, người làm Key Mgmt mở rộng)
| Cột | Kiểu |
|---|---|
| `key_id` | CHAR(36) PK |
| `user_id` | FK `User` |
| `purpose` | ENUM('ENCRYPTION','SIGNING') |
| `algorithm` | VARCHAR(32), giá trị `RSA-OAEP-3072-SHA256` hoặc `ECDSA-P256-SHA256` |
| `public_key_jwk` | JSON |
| `fingerprint` | CHAR(64) UNIQUE (SHA-256 hex của JCS(public JWK)) |
| `status` | ENUM('PENDING_VERIFICATION','ACTIVE','RETIRED','COMPROMISED') DEFAULT 'PENDING_VERIFICATION' |
| `created_at`, `activated_at` NULL | |
| `active_marker` | cột sinh tự động: `CASE WHEN status='ACTIVE' THEN 1 END`, UNIQUE `(user_id, purpose, active_marker)` |

### 010 `Document`
| Cột | Kiểu |
|---|---|
| `document_id` | CHAR(36) PK |
| `folder_id` | FK `Treatment_Folder` |
| `document_name` | VARCHAR(255) NOT NULL |
| `category` | ENUM('MEDICAL_REPORT','LABORATORY_RESULT','PRESCRIPTION','MEDICAL_IMAGE','OTHER') |
| `original_uploader_id` | FK `User` |
| `current_version_id` | CHAR(36) NULL (FK tới `Document_Version`, thêm ở migration 011) |
| `created_at`, `updated_at` | DATETIME(3) |
| index | `(folder_id, updated_at)`, `(folder_id, document_name)` |

### 011 `Document_Version` (business version, không bao giờ sửa sau khi tạo)
| Cột | Kiểu |
|---|---|
| `version_id` | CHAR(36) PK |
| `document_id` | FK `Document` |
| `version_number` | INT UNSIGNED, UNIQUE `(document_id, version_number)` |
| `base_version_id` | CHAR(36) NULL, FK tới chính bảng này |
| `created_by` | FK `User` |
| `author_key_id` | FK `User_Key` |
| `mime_type` | VARCHAR(127) NOT NULL |
| `created_at` | DATETIME(3) |

Migration này cũng chạy `ALTER TABLE Document ADD CONSTRAINT fk_document_current_version ...`.

### 012 `Crypto_Revision`
| Cột | Kiểu |
|---|---|
| `revision_id` | CHAR(36) PK |
| `version_id` | FK `Document_Version` |
| `revision_number` | INT UNSIGNED, UNIQUE `(version_id, revision_number)` |
| `status` | ENUM('STAGED','ACTIVE','SUPERSEDED') |
| `active_marker` | cột sinh tự động, UNIQUE `(version_id, active_marker)`, đảm bảo mỗi version có đúng một revision ACTIVE |
| `storage_object_key` | VARCHAR(80) UNIQUE |
| `ciphertext_size` | BIGINT UNSIGNED |
| `ciphertext_sha256` | CHAR(64) |
| `aead_algorithm` | VARCHAR(16) DEFAULT 'AES-256-GCM' |
| `nonce` | VARBINARY(12) |
| `policy_version` | INT UNSIGNED. Phiên bản policy của folder tại lúc tạo revision |
| `signed_manifest` | JSON (`{ manifest, signature }`) |
| `signer_key_id` | FK `User_Key` |
| `created_by` | FK `User` |
| `created_at`, `activated_at` | DATETIME(3) |

Tag GCM 16 byte nằm cuối ciphertext, đúng với cách WebCrypto xuất ra.

### 013 `DEK_Envelope`
| Cột | Kiểu |
|---|---|
| `envelope_id` | BIGINT UNSIGNED AUTO_INCREMENT PK |
| `revision_id` | FK `Crypto_Revision` |
| `recipient_user_id` | FK `User` |
| `recipient_membership_id` | FK `Folder_Membership` |
| `recipient_key_id` | FK `User_Key` |
| `wrapped_dek` | VARBINARY(512), bắt buộc đúng 384 byte (RSA-OAEP-3072) |
| `created_at` | DATETIME(3) |
| ràng buộc | UNIQUE `(revision_id, recipient_user_id)`, index `(recipient_user_id, revision_id)` |

### 014 `Upload_Context`
| Cột | Kiểu |
|---|---|
| `context_id` | CHAR(36) PK |
| `folder_id` | FK `Treatment_Folder` |
| `user_id` | FK `User` |
| `purpose` | ENUM('NEW_DOCUMENT','NEW_VERSION') |
| `document_id`, `version_id`, `revision_id` | CHAR(36) do server cấp. Không đặt FK vì với `NEW_DOCUMENT` thì document chưa tồn tại |
| `base_version_id` | CHAR(36) NULL |
| `version_number` | INT UNSIGNED |
| `policy_version` | INT UNSIGNED |
| `signer_key_id` | CHAR(36). Key ký ACTIVE của người upload tại lúc cấp context |
| `recipients` | JSON: `[{ userId, membershipId, keyId, fingerprint }]`, sắp xếp theo `userId` |
| `expires_at`, `consumed_at` NULL, `created_at` | DATETIME(3) |

## 6. Quy tắc chung của mọi endpoint

- **Danh tính:** lấy từ `request.user.id` (chuỗi số). Thiếu thì trả `401 UNAUTHENTICATED`.
- **Quyền:** dùng lại `hasFolderPermission` mà `folder-router.js` đã export, không sửa file đó. Các action dùng:
  - `read`: Owner, Editor, Viewer.
  - `upload`, `updateDocument`: Owner, Editor.
  - `deleteDocument`: chỉ Owner.
- **Folder sẵn sàng (BR-13, FR-KEY-10).** Folder được coi là sẵn sàng khi thỏa cả ba:
  1. Không có dòng nào trong `Folder_Deletion_Operation`.
  2. Rotation job tại `MAX(policy_version)` không tồn tại, hoặc có `status = 'COMPLETED'`.
  3. Có ít nhất một dòng `Folder_Policy`.

  Đây cùng là cách `findForUser` của folders tính `cryptoState`: không có job thì là `null`, job `COMPLETED` thì là `READY`. Nếu folder không sẵn sàng thì trả `409 FOLDER_NOT_READY`. Quy tắc này áp dụng cho upload-context, upload, version mới, manifest, content và delete. List và metadata vẫn đọc được bình thường.
- **Không để lộ sự tồn tại:**
  - Document hoặc version không tồn tại, hoặc người gọi không có membership ACTIVE ở folder chứa nó: trả `404 DOCUMENT_NOT_FOUND` / `VERSION_NOT_FOUND`.
  - Có membership nhưng role không đủ: trả `403 FORBIDDEN`.
  - Với các endpoint có `:folderId`, người không phải thành viên nhận `403 FORBIDDEN`, giống folders.
- **Cache:** mọi response có `Cache-Control: no-store`.
- **Định dạng ID và thời gian:**
  - UUID dạng chữ thường, kiểm tra bằng regex giống folders.
  - Thời gian trả về dạng ISO-8601 UTC.
  - Dữ liệu nhị phân trong JSON mã hóa base64url không padding.

## 7. Endpoints

### 7.1 `GET /api/v1/folders/:folderId/documents` → `listFolderDocuments` (O/E/V)
- **Query:**
  - `query`: tối đa 100 ký tự, tìm bằng `LIKE` trên `document_name`, có escape `%` và `_`.
  - `category`: một trong 5 giá trị.
  - `page`: mặc định 1. Mỗi trang 50 mục.
- **Response `200`:**
  ```
  { documents: [{ documentId, folderId, documentName, category, originalUploaderId,
                  currentVersionId, currentVersionNumber, ciphertextSize, createdAt, updatedAt }],
    nextPage }
  ```
  Sắp xếp theo `updatedAt DESC, documentId`. `nextPage` là số trang kế tiếp hoặc `null`.

### 7.2 `POST /api/v1/folders/:folderId/upload-contexts` → `createUploadContext` (O/E)
- **Body:** `{ "purpose": "NEW_DOCUMENT" }` hoặc `{ "purpose": "NEW_VERSION", "documentId", "baseVersionId" }`.
- **Kiểm tra trong một transaction:**
  1. Khóa folder.
  2. Role thuộc `upload`.
  3. Folder sẵn sàng.
  4. Người gọi có key ký ACTIVE. Nếu không thì trả `409 SIGNING_KEY_MISSING`.
  5. Mọi thành viên ACTIVE có key mã hóa ACTIVE. Nếu không thì trả `409 RECIPIENT_KEY_MISSING` kèm `userIds`.
  6. Riêng `NEW_VERSION`: document thuộc folder này, và `baseVersionId === current_version_id`. Nếu không khớp thì trả `409 VERSION_CONFLICT` kèm `currentVersionId`.
- **Response `201`:**
  ```
  { contextId, purpose, folderId, documentId, versionId, revisionId, versionNumber,
    baseVersionId, policyVersion, signerKeyId, expiresAt,
    recipients: [{ userId, membershipId, keyId, fingerprint, publicKeyJwk }] }
  ```
  Server không sinh và không nhận DEK.

### 7.3 `POST /api/v1/folders/:folderId/documents` → `uploadDocument` (O/E)

**Request:** `multipart/form-data`, gồm đúng hai phần:
- `metadata`: field dạng chuỗi JSON:
  ```
  { contextId, documentName, category, mimeType, manifest, signature,
    envelopes: [{ userId, keyId, wrappedDek }] }
  ```
- `ciphertext`: file, tối đa `MAX_UPLOAD_MB`.

**Xử lý:**
1. **Router:**
   - Parse và validate. `documentName` từ 1 đến 255 ký tự sau khi trim. `mimeType` khớp `type/subtype`.
   - Tính `sha256(ciphertext)` và kích thước.
   - So với `manifest.ciphertextSha256` và `manifest.ciphertextSize`. Lệch thì trả `422 CIPHERTEXT_HASH_MISMATCH`.
2. **Ghi object:** sinh `objectKey = <manifest.revisionId>/<randomUUID()>` rồi gọi `storage.put`. `revisionId` phải là UUID hợp lệ trước khi dùng làm key.
3. **Repository, trong một transaction:**
   1. Khóa `Treatment_Folder`, rồi khóa `Upload_Context` bằng `FOR UPDATE`.
   2. Kiểm tra context: đúng user, đúng folder, đúng purpose. Không tìm thấy thì trả `409 CONTEXT_NOT_FOUND`. Đã dùng thì trả `409 CONTEXT_USED`. Hết hạn thì trả `409 CONTEXT_EXPIRED`.
   3. Kiểm tra lại role `upload` và folder sẵn sàng.
   4. `MAX(policy_version)` vẫn bằng `context.policy_version`. Nếu đã đổi thì trả `409 CONTEXT_STALE`.
   5. Key ký `context.signer_key_id` vẫn ACTIVE. Nếu không thì trả `409 SIGNING_KEY_MISSING`.
   6. `manifest` phải bằng `buildExpectedManifest(context, upload)` theo JCS, trừ các trường do client tính: `aead.nonce`, `ciphertextSha256`, `ciphertextSize`, `authorRecordSha256`, `recipients[].wrappedDekSha256`. Các trường đó chỉ cần đúng định dạng. Lệch thì trả `422 MANIFEST_MISMATCH`.
   7. Chữ ký hợp lệ với public key ký. Nếu không thì trả `422 INVALID_SIGNATURE`.
   8. Tập `envelopes` khớp chính xác `context.recipients` theo `(userId, keyId)`: không thiếu, không thừa, không trùng. Mỗi `wrappedDek` giải mã ra đúng 384 byte, và `sha256(wrappedDek)` bằng `manifest.recipients[i].wrappedDekSha256`. Lệch thì trả `422 RECIPIENTS_MISMATCH`.
   9. Insert `Document`, `Document_Version` (version 1, `author_key_id = signer_key_id`), `Crypto_Revision` (revision 1, ACTIVE), các `DEK_Envelope`. Đặt `Document.current_version_id`. Cập nhật `Upload_Context.consumed_at`. Commit.
4. **Nếu repository trả lỗi hoặc ném exception:** gọi `storage.delete(objectKey)` (lỗi ở bước này chỉ log). Nếu server sập giữa bước 2 và 3 thì có thể còn sót object rác. Điểm này đã ghi vào takenote.

**Response `201`:** `{ documentId, versionId, revisionId, versionNumber }`, kèm header `Location: /api/v1/documents/:documentId`.

### 7.4 Manifest được ký
Định dạng do nhóm Documents đề xuất và cần Crypto/FE xác nhận. Xem takenote.

```json
{
  "purpose": "DOCUMENT_VERSION_UPLOAD",
  "contextId": "uuid", "folderId": "uuid", "documentId": "uuid",
  "versionId": "uuid", "revisionId": "uuid",
  "versionNumber": 1, "baseVersionId": null,
  "policyVersion": 3,
  "actorUserId": "12", "signerKeyId": "uuid",
  "aead": { "alg": "AES-256-GCM", "nonce": "<base64url 12 byte>" },
  "ciphertextSha256": "<hex 64>", "ciphertextSize": 12345,
  "authorRecordSha256": "<hex 64>",
  "recipients": [ { "userId": "12", "keyId": "uuid", "wrappedDekSha256": "<hex 64>" } ]
}
```
- **Cách ký:** `signature = base64url(ECDSA_P256_SHA256(JCS(manifest)))`, chữ ký dạng IEEE-P1363 dài 64 byte. Giống cách verify folder policy trong `folder-policy-signatures.js`.
- **Thứ tự:** `recipients` sắp theo `userId` (so sánh dạng số), cùng thứ tự với `context.recipients`.
- **AAD:** client dùng `JCS({ folderId, documentId, versionId, revisionId, purpose })` làm AAD cho AES-GCM. Backend không giải mã nên không kiểm tra AAD. Quy ước này ghi ra để FE và Crypto thống nhất.
- **AuthorRecord** nằm trong container đã mã hóa, backend không đọc được. Backend chỉ lưu `authorRecordSha256` đã được ký.

### 7.5 `GET /api/v1/documents/:documentId` → `getDocument` (O/E/V)
Response `200` gồm: `{ documentId, folderId, documentName, category, originalUploaderId, currentVersionId, currentVersionNumber, role, createdAt, updatedAt }`.

### 7.6 `PATCH /api/v1/documents/:documentId` → `updateDocumentMetadata` (O/E)
- **Body:** chỉ có `documentName` và/hoặc `category`, phải có ít nhất một trường. Có trường khác thì trả `400 INVALID_DOCUMENT_INPUT`.
- **Xử lý:** trong transaction, khóa folder rồi khóa document, kiểm tra lại role, sau đó cập nhật và đặt `updated_at`.
- **Folder sẵn sàng:** không bắt buộc, vì đây là metadata, không phải nội dung.
- **Response `200`:** giống 7.5.

### 7.7 `DELETE /api/v1/documents/:documentId` → `deleteDocument` (O)
1. Trong transaction: khóa folder rồi khóa document. Kiểm tra role `deleteDocument` và folder sẵn sàng.
2. Thu thập `storage_object_key` của mọi revision.
3. Xóa theo thứ tự: `DEK_Envelope`, `Crypto_Revision`, đặt `Document.current_version_id = NULL`, xóa `Document_Version`, xóa `Upload_Context` của document đó, xóa `Document`. Commit.
4. Sau khi commit: `storage.delete` từng object. Lỗi ở bước này chỉ log.

Response `204`.

### 7.8 `GET /api/v1/documents/:documentId/versions` → `listDocumentVersions` (O/E/V)
- **Response `200`:**
  ```
  { versions: [{ versionId, versionNumber, baseVersionId, createdBy, mimeType,
                 ciphertextSize, createdAt, isCurrent }] }
  ```
- `ciphertextSize` lấy từ revision ACTIVE.
- Sắp xếp theo `versionNumber DESC`.
- Crypto revision không tạo dòng mới trong danh sách.

### 7.9 `POST /api/v1/documents/:documentId/versions` → `createDocumentVersion` (O/E)
- Cùng request multipart như 7.3, nhưng context phải có `purpose = NEW_VERSION` và cùng `documentId`. `documentName` và `category` trong metadata không bắt buộc và bị bỏ qua.
- Trong transaction, kiểm tra thêm sau khi khóa `Document`: `current_version_id` vẫn bằng `context.base_version_id`. Nếu không thì trả `409 VERSION_CONFLICT` kèm `currentVersionId` (FR-DOC-06).
- `version_number` bằng số lớn nhất hiện có cộng 1, đã chốt từ lúc cấp context và được kiểm tra lại.
- Insert version, revision và envelopes, cập nhật `current_version_id` và `Document.updated_at`.

Response `201`: `{ documentId, versionId, revisionId, versionNumber }`.

### 7.10 `GET /api/v1/versions/:versionId/manifest` → `getVersionManifest` (O/E/V)
- **Điều kiện:** role `read` và folder sẵn sàng.
- **Response `200`:**
  ```
  { versionId, documentId, folderId, revisionId, manifest, signature,
    signer: { userId, keyId, publicKeyJwk },
    envelope: { keyId, wrappedDek } }
  ```
- Chỉ trả envelope của người gọi (FR-KEY-06), lấy theo revision ACTIVE.
- Nếu người gọi không có envelope thì trả `409 ENVELOPE_NOT_AVAILABLE`.

### 7.11 `GET /api/v1/versions/:versionId/content?revisionId=<uuid>` → `downloadVersionCiphertext` (O/E/V)
- **Điều kiện:** role `read`, folder sẵn sàng.
- **Kiểm tra revision:** nếu client gửi `revisionId` mà khác revision ACTIVE thì trả `409 REVISION_CHANGED` kèm `revisionId` hiện tại.
- **Response `200`:** `Content-Type: application/octet-stream`, `Content-Length`, `X-Crypto-Revision-Id`, `Cache-Control: no-store`, body là ciphertext.

## 8. Bảng mã lỗi

| HTTP | Code |
|---|---|
| 400 | `INVALID_DOCUMENT_INPUT`, `INVALID_UPLOAD_CONTEXT_INPUT`, `INVALID_DOCUMENT_ID`, `INVALID_VERSION_ID`, `INVALID_DOCUMENT_PAGE`, `INVALID_JSON` |
| 401 | `UNAUTHENTICATED` |
| 403 | `FORBIDDEN` |
| 404 | `DOCUMENT_NOT_FOUND`, `VERSION_NOT_FOUND` |
| 409 | `FOLDER_NOT_READY`, `CONTEXT_NOT_FOUND`, `CONTEXT_USED`, `CONTEXT_EXPIRED`, `CONTEXT_STALE`, `VERSION_CONFLICT`, `SIGNING_KEY_MISSING`, `RECIPIENT_KEY_MISSING`, `ENVELOPE_NOT_AVAILABLE`, `REVISION_CHANGED` |
| 413 | `PAYLOAD_TOO_LARGE` |
| 422 | `INVALID_SIGNATURE`, `MANIFEST_MISMATCH`, `CIPHERTEXT_HASH_MISMATCH`, `RECIPIENTS_MISMATCH` |
| 503 | `DOCUMENT_SERVICE_UNAVAILABLE` |
| 500 | `INTERNAL_ERROR` (qua error handler có sẵn của `createApp`; không log nội dung request) |

## 9. Công cụ dev

- **`docker compose up -d`:** chạy MySQL 8. Database và user lấy từ `.env`.
- **`npm run migrate`** (`scripts/migrate.cjs`):
  - Tạo bảng `schema_migrations(filename PK, applied_at)` nếu chưa có.
  - Chạy lần lượt các file `migrations/*.sql` chưa được áp dụng, theo thứ tự tên file. Ghi lại sau mỗi file thành công.
  - Dừng ngay ở file lỗi.
  - DDL của MySQL tự commit, nên file lỗi giữa chừng phải sửa tay. Hướng dẫn ghi trong README.
- **`npm run seed`** (`scripts/seed.cjs`), chỉ chạy khi `NODE_ENV !== 'production'`:
  1. Tạo 16 tài khoản: 1 `ADMIN` và 15 `STAFF` (`staff01@medshare.test` … `staff15@medshare.test`).
  2. Sinh key RSA-OAEP-3072 và ECDSA P-256 cho mỗi STAFF, lưu public key ở trạng thái `ACTIVE`. Private key ghi ra `backend/data/dev-keys/<userId>.json` (đã gitignore, chỉ phục vụ test).
  3. Tạo 3 folder mẫu bằng chính `createApp` và API folders (initial policy có chữ ký, policy context, thêm thành viên). Mục đích là để có đủ tổ hợp Owner/Editor/Viewer và người ngoài folder. Ví dụ: staff01 là Owner folder A, staff02 là Editor folder A nhưng là Owner folder B.
  4. Hoàn tất rotation job của các folder mẫu, vì folder còn trống nên không có gì phải mã hóa lại.
  5. Nếu email đã tồn tại thì dừng. Muốn làm lại từ đầu thì chạy `docker compose down -v` rồi migrate và seed lại.
- **`npm run dev:complete-rotations -- <folderId>`** (`scripts/dev-complete-rotations.cjs`):
  - **Vấn đề:** rotation commit chưa có, nên sau khi thêm hoặc thu hồi thành viên, folder bị chặn thao tác nội dung mãi mãi.
  - **Script làm gì:** đặt các job chưa xong của folder đó thành `COMPLETED`, để dev và FE tiếp tục test được.
  - **Giới hạn:** chỉ chạy khi `NODE_ENV !== 'production'`. Nếu folder đã có tài liệu, script in cảnh báo: thành viên mới sẽ chưa có envelope (`ENVELOPE_NOT_AVAILABLE`), và DEK chưa được xoay.
  - Đây chỉ là công cụ dev, không phải hành vi của sản phẩm.
- **`npm run smoke:documents`** (`scripts/smoke-documents.cjs`): xem mục 10.

## 10. Kiểm thử

- **`npm test`** (dùng `node --test`, không cần MySQL hay mạng):
  - `test/document-manifest.test.js`: ký bằng key sinh trong test rồi verify thành công. Sửa từng trường một, đổi key, chữ ký sai độ dài hay sai encoding thì đều bị từ chối. Thiếu, thừa hoặc trùng envelope, hoặc độ dài 383 hay 385 byte, đều bị từ chối.
  - `test/local-object-storage.test.js`: put/get/delete. Key xấu (`../x`, đường dẫn tuyệt đối, sai regex) bị từ chối. Xóa file không tồn tại vẫn thành công.
  - `test/config.test.js`: thiếu `DB_PASSWORD` thì lỗi. `AUTH_MODE=dev` khi `NODE_ENV=production` thì lỗi.
  - `test/dev-header-auth.test.js`.
  - `test/documents.test.js`: router với repository và storage giả lập.
    - Ma trận quyền O/E/V cho từng endpoint, 401, mã lỗi 404 và 403.
    - Validate input, multipart thiếu phần, vượt giới hạn thì 413, hash lệch thì 422.
    - Object bị xóa khi repository trả lỗi.
  - `test/mysql-document-repository.test.js`: connection giả lập, giống `mysql-folder-repository.test.js`.
    - Thứ tự khóa folder → context → document.
    - Rollback và release connection khi lỗi.
    - `VERSION_CONFLICT` khi base đã đổi, `CONTEXT_STALE` khi policy đã đổi.
  - 16 test hiện có của folders phải tiếp tục pass.
- **`npm run smoke:documents`** (cần Docker MySQL, đã migrate và seed):
  1. Owner xin context rồi upload một ciphertext mã hóa thật bằng AES-256-GCM trong Node, với envelope RSA-OAEP thật cho mọi thành viên.
  2. Viewer lấy manifest và content, unwrap DEK, giải mã ra đúng bản gốc.
  3. Editor tạo V2. Upload lần nữa trên base V1 thì nhận `409 VERSION_CONFLICT`.
  4. Viewer gọi upload-context thì nhận `403`. Người ngoài folder gọi `GET /documents/:id` thì nhận `404`.
  5. Owner thêm thành viên. Folder chuyển sang `FOLDER_NOT_READY`. Chạy `dev:complete-rotations`. Thành viên mới nhận `ENVELOPE_NOT_AVAILABLE`.
  6. Owner xóa tài liệu. Kiểm tra object đã biến mất khỏi `STORAGE_DIR`.
  7. Dashboard `documentCount` thay đổi đúng.

## 11. Điểm cần nhóm xác nhận
Xem chi tiết và lý do trong `takenote.md`:
- Định dạng manifest, AAD, encoding envelope, tên field multipart (Crypto, FE).
- Bảng `User` và `User_Key` tối thiểu, quy ước `request.user.id` là chuỗi số (Auth, Key Mgmt).
- Editor không được xóa tài liệu (theo API list, khác BRD).
- Giới hạn 25 MB.
- Dọn tài liệu khi xóa folder (Folder).
- Ghi Audit cho sự kiện tài liệu (FR-AUDIT-01).
- Download bị chặn khi folder đang rotation, và tool `dev:complete-rotations` (Rotation, cả nhóm).
