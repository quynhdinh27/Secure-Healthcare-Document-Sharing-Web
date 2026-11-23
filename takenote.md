# Take note: Document Management (backend)

File này ghi lại mọi chỗ mà phần Document Management (và phần Data đi kèm) **khác với ERD hoặc các tài liệu nhóm**, kèm lý do. Mục cuối liệt kê những việc cần nhóm chốt.

Thiết kế đầy đủ: `docs/superpowers/specs/2026-11-23-document-management-design.md`.

Thứ tự ưu tiên khi các tài liệu mâu thuẫn: **API list (17/11) > System design > FRS / BRD / Use cases > ERD**.

---

## 1. Khác với ERD

### 1.1 Bảng mới, ERD chưa có

| Bảng | Lý do | Nguồn |
|---|---|---|
| `Crypto_Revision` | API list yêu cầu tách business version (V1, V2) khỏi crypto revision. Rotation tạo revision mới nhưng không tạo version mới. Chính ghi chú trong Crypto ERD cũng viết: *"needs a separate crypto-revision/history entity"*. | API list mục "Quyền, version…", BR-14, Crypto ERD (Design notes) |
| `Upload_Context` | `createUploadContext` cấp context dùng một lần, có hạn sử dụng, chứa danh sách người nhận. Context phải được lưu lại để lúc upload kiểm tra. | API list mục 3, System design 11.2 và 12.1 |
| `schema_migrations` | Bảng nội bộ của migration runner, ghi lại các file migration đã chạy. | Không có trong tài liệu nào (công cụ kỹ thuật) |

### 1.2 `Document`

| ERD | Thực hiện | Lý do |
|---|---|---|
| `document_id` (kiểu chưa ghi) | `CHAR(36)` UUID do server cấp | Thống nhất với `folder_id`. ID được cấp trong upload context để client đưa vào manifest và AAD trước khi upload. |
| `current_owner_id` | **Bỏ** | Owner là role ở cấp folder (BR-02, BR-03). Tài liệu không có owner riêng. |
| không có | **Thêm** `current_version_id` | API list: "cách xác định bản hiện hành của Document" và `getDocument` trả `currentVersionId`. |
| `category` (chưa có danh sách giá trị) | ENUM gồm 5 giá trị: `MEDICAL_REPORT`, `LABORATORY_RESULT`, `PRESCRIPTION`, `MEDICAL_IMAGE`, `OTHER` | BRD 2.4, mục Supported Document Categories |

### 1.3 `Document_Version`

| ERD | Thực hiện | Lý do |
|---|---|---|
| `storage_object_key`, `nonce`, `ciphertext_hash`, `encryption_algorithm` | **Chuyển** sang `Crypto_Revision` | Mỗi lần rotation tạo ciphertext mới với nonce và hash mới. Nếu để trên version thì phải ghi đè. |
| `authentication_tag` | **Bỏ** | Tag GCM nằm cuối ciphertext, theo cách WebCrypto xuất ra. Hash của ciphertext đã bao gồm tag. |
| `plaintext_hash` | **Bỏ** | API list (`getVersionManifest`) ghi: *"không có plaintext hash bệnh án"*. Hash bản rõ nằm trong AuthorRecord đã mã hóa (System design 12.4), và manifest chỉ chứa `authorRecordSha256`. |
| `file_size` | Thay bằng `ciphertext_size` (lưu ở `Crypto_Revision`) | Backend chỉ biết kích thước ciphertext. Kích thước bản rõ bằng kích thước ciphertext trừ 16 byte tag. |
| không có | **Thêm** `base_version_id` | FR-DOC-05: version mới phải liên kết với base version. Ngoài ra cần để phát hiện xung đột (FR-DOC-06). |
| không có | **Thêm** `author_key_id` | Lưu key ký của tác giả để verify chữ ký về sau (System design 8, Layer 2). |

### 1.4 `DEK_Envelope`

| ERD | Thực hiện | Lý do |
|---|---|---|
| `encapsulated_key`, `wrap_nonce`, `wrap_auth_tag`, `kdf_salt`, `wrapped_dek BINARY(32)` | **Bỏ** và thay bằng `wrapped_dek VARBINARY(512)`, độ dài bắt buộc 384 byte | Các cột cũ thuộc thiết kế ElGamal KEM/DEM. System design mục 6 đã chốt RSA-OAEP-3072, và ghi rõ *"ElGamal is not used"*. Kết quả RSA-OAEP-3072 dài 384 byte. |
| `version_id` | Đổi thành `revision_id` | Mỗi crypto revision có DEK riêng (BR-09), nên envelope phải gắn với revision. |
| không có | **Thêm** `recipient_user_id` | Để tra nhanh "envelope của chính mình" (FR-KEY-06), và đặt UNIQUE `(revision_id, recipient_user_id)`. |
| `membership_id`, `recipient_key_id` | Giữ nguyên, đổi tên thành `recipient_membership_id` và `recipient_key_id` | |

### 1.5 `User` (bản tối thiểu, chờ bạn làm Auth mở rộng)

| ERD | Thực hiện | Lý do |
|---|---|---|
| `department_id`, `password_hash` | **Chưa có** | Thuộc phần Auth và bảng `Department` chưa có. Bạn Auth thêm bằng `ALTER TABLE`. |
| `email` (UNIQUE), `full_name` | Có, nhưng **cho phép NULL** | Smoke script của folders (`smoke-folder-membership.cjs`) chỉ insert `user_id`. Bạn Auth có thể đổi sang NOT NULL sau khi sửa script đó. |
| `account_type`, `account_status` | ENUM `STAFF`/`ADMIN` và `ACTIVE`/`DISABLED` | ERD không ghi danh sách giá trị. Chọn theo BRD 2.3 và FR-ADMIN-01. |
| `user_id` | `BIGINT UNSIGNED AUTO_INCREMENT` | Khớp với các khóa ngoại sẵn có trong migration 002 của folders. |

Migration mang số `000` để chạy trước `002`, vì `002` có khóa ngoại tới `User`.

### 1.6 `User_Key` (bản tối thiểu, chờ bạn làm Key Mgmt mở rộng)

| ERD | Thực hiện | Lý do |
|---|---|---|
| `status` ACTIVE/REVOKED/COMPROMISED | `PENDING_VERIFICATION`/`ACTIVE`/`RETIRED`/`COMPROMISED` | FR-KEY-08 và System design 10.2 |
| `public_key BLOB`, `key_algorithm`, `key_parameters` | `public_key_jwk JSON`, `algorithm` | Code folders đã verify chữ ký bằng JWK (`folder-policy-signatures.js`). WebCrypto xuất JWK trực tiếp. |
| không có | **Thêm** `purpose` (`ENCRYPTION`/`SIGNING`) | System design 7: hai cặp key tách riêng, không dùng chung một cặp cho cả mã hóa và ký. |
| không có | **Thêm** `fingerprint` | System design 6: dùng SHA-256 làm fingerprint public key. Client cần để kiểm tra recipient. |
| `revoked_at` | Đổi thành `activated_at` | Các mốc thời gian còn lại để bạn Key Mgmt bổ sung. |
| `User_Key_Backup`, `User_Device`, `Key_Rotation_Log` | **Chưa tạo** | Không thuộc Document Management. |

---

## 2. Khác với tài liệu khác, hoặc phải chọn giữa các tài liệu

| # | Nội dung | Các tài liệu nói gì | Chọn | Lý do |
|---|---|---|---|---|
| 2.1 | Editor xóa tài liệu do chính mình upload | BRD (Role clarification): **được**. FRS 17.2, FR-DOC-07, UC-08 và API list: **không** | **Không được** | API list là bản mới nhất (17/11). Code folders cũng đã đặt `deleteDocument` chỉ cho Owner. |
| 2.2 | Thuật toán bọc DEK | Proposal, Pain point, flows drawio, ERD: **ElGamal**. System design 6 và bảng task (Crypto đã làm xong RSA): **RSA-OAEP-3072** | **RSA-OAEP-3072** | System design ghi rõ ElGamal không dùng nữa, và module Crypto đã triển khai RSA. |
| 2.3 | Revoke có xoay DEK không | UC-04 (Postconditions): ciphertext và DEK giữ nguyên. System design 13 và API list: revoke kích hoạt rotation | **Có rotation.** Documents chặn thao tác nội dung khi folder chưa `READY` | Theo API list và BR-13. Bản thân Documents không xoay DEK. |
| 2.4 | Khi revoke thì envelope cũ xử lý thế nào | UC-04: *"The member's active DEK envelopes are removed"* | **Không xóa ngay.** Người bị thu hồi bị chặn ngay ở API (BR-12). Envelope cũ chỉ bị thay thế khi rotation commit | Xóa envelope không thu hồi được DEK mà người đó đã tải về. Rotation mới là cơ chế bảo vệ đúng (System design 5.2, 13.4). |
| 2.5 | Thông tin nào được lưu dạng rõ | API list: *"chỉ tìm metadata rõ được phép lưu"*. System design: giữ metadata nhạy cảm trong container | `document_name`, `category`, `mime_type` lưu dạng rõ. Mọi nội dung bệnh án nằm trong container mã hóa | Cần tên và category để list và tìm kiếm (FILE-03, `listFolderDocuments`). **FE nên tránh đặt tên file chứa thông tin bệnh nhân.** |
| 2.6 | Thông tin trong UI khi xem chi tiết (FILE-04: tên, kích thước, ngày) | Proposal | Kích thước hiển thị là `ciphertextSize` | Backend không biết kích thước bản rõ. Chênh lệch chỉ 16 byte. |
| 2.7 | Folder chưa từng có rotation job (`cryptoState = null`) | BR-13 yêu cầu `READY` mới cho thao tác nội dung | **Coi là sẵn sàng** | Folder mới tạo chưa có job nào. Nếu bắt buộc `READY` thì folder mới không bao giờ upload được. |
| 2.8 | Download khi folder đang rotation | System design 12.2: backend kiểm tra folder `READY`. BR-13: chặn thao tác nội dung thông thường | **Chặn** cả manifest và content (`409 FOLDER_NOT_READY`). List và metadata vẫn xem được | Bám đúng tài liệu. Ảnh hưởng UX: sau khi Owner thêm thành viên, không ai tải được file cho tới khi rotation xong. **Cần nhóm xác nhận.** |
| 2.9 | Lỗi khi không có quyền | Folders trả `403 FORBIDDEN` | Với document và version: trả `404` nếu không phải thành viên, `403` nếu là thành viên nhưng thiếu quyền | ID tài liệu do server cấp. Trả 404 để không lộ việc tài liệu có tồn tại. Với endpoint có `:folderId` thì giữ 403 giống folders. |

---

## 3. Điểm chạm với phần của người khác

| File / bảng | Thay đổi | Ảnh hưởng tới ai |
|---|---|---|
| `src/server.js` | **Chỉ thêm code.** `createApp` nhận thêm `documentRepository`, `objectStorage`, `keyDirectory`, `maxUploadBytes`, rồi gắn router Documents. Nếu có `keyDirectory` thì dùng nó làm `folderPolicyKeys` mặc định. Không sửa route nào đang có. | Cả nhóm (file chung) |
| `src/main.js` (mới) và `npm start` | `npm start` đổi từ `node src/server.js` sang `node src/main.js`. `main.js` đọc env, tạo MySQL pool, chọn auth và storage. | Cả nhóm |
| `package.json` | Thêm `mysql2` (smoke script của folders vốn đã dùng nhưng chưa khai báo), `multer`, và các script `migrate`, `seed`, `dev:complete-rotations`, `smoke:documents`. | Cả nhóm |
| Bảng `User` (`000`) | Bản tối thiểu | **Auth**: mở rộng bằng `ALTER TABLE` |
| Bảng `User_Key` (`009`) và `src/keys/mysql-key-directory.js` | Bản tối thiểu, chỉ đọc. Không có endpoint | **Key Mgmt**: thêm register/activate/backup trên cùng bảng, có thể thay thế file này |
| `src/auth/dev-header-auth.js` | Auth giả lập qua header `X-Dev-User-Id`. Bị chặn khi `NODE_ENV=production` | **Auth**: viết middleware thật gán `request.user = { id: '<chuỗi số>' }`, rồi thêm `AUTH_MODE=session` trong `main.js` |
| `scripts/dev-complete-rotations.cjs` | Công cụ dev đặt rotation job thành `COMPLETED`, vì rotation commit chưa có | **Rotation / Key Mgmt**: bỏ công cụ này khi `commitRotation` hoàn thành |

Không sửa: `src/folders/*`, migration `001`–`008`, test của folders, `scripts/smoke-folder-membership.cjs`.

---

## 4. Rủi ro và giới hạn đã biết

- **Object rác.** Nếu server sập sau khi ghi ciphertext vào storage nhưng trước khi transaction commit, sẽ còn sót object không có dòng DB nào trỏ tới. Hiện chưa có job dọn dẹp.
- **Xóa tài liệu.** DB được xóa trước, sau đó mới xóa object storage. Nếu bước xóa object lỗi thì còn sót file ciphertext, chỉ được ghi log. Ciphertext không đọc được nếu không có DEK.
- **Seed lưu private key ra file** `backend/data/dev-keys/` để test. Thư mục này chỉ dùng khi dev, đã gitignore, **không bao giờ dùng cho deploy.**
- **Migration MySQL không rollback được DDL.** File lỗi giữa chừng phải sửa tay hoặc chạy lại DB từ đầu (`docker compose down -v`).

---

## 5. Cần nhóm chốt

| # | Điểm cần chốt | Hỏi ai |
|---|---|---|
| 5.1 | Định dạng CryptoManifest (spec mục 7.4), quy ước AAD, encoding base64url, tên field multipart (`metadata`, `ciphertext`) | Crypto, FE |
| 5.2 | Bảng `User` và `User_Key` tối thiểu có dùng làm nền chung không. Quy ước `request.user.id` là chuỗi số | Auth, Key Mgmt |
| 5.3 | Editor không được xóa tài liệu (mục 2.1) | Cả nhóm |
| 5.4 | Giới hạn upload 25 MB (`MAX_UPLOAD_MB`) | Cả nhóm |
| 5.5 | Khi xóa folder: phải xóa `DEK_Envelope`, `Crypto_Revision`, `Document_Version`, `Document`, `Upload_Context` và object storage. Hiện `deleteForOwner` mới tạo operation và thu hồi membership, chưa dọn dữ liệu | Người làm Folder |
| 5.6 | Ghi `Audit_Log` cho upload, version mới, download, xóa (FR-AUDIT-01). Documents chưa ghi | Người làm Audit / Operations |
| 5.7 | Chặn download khi folder đang rotation (mục 2.8), và cách xử lý trước khi rotation commit hoàn thành | Rotation, cả nhóm |
| 5.8 | Tài liệu `KMDM_ARCHITECTURE.md` mà API list tham chiếu nhưng không có trong thư mục tài liệu | Người viết API list |
