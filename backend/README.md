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
| `npm run smoke:documents` | Kiểm tra upload, giải mã và xoay khóa sau khi thêm hoặc thu hồi thành viên trên MySQL |
| `npm run dev:complete-rotations -- <folderId>` | **Chỉ dev.** Hoàn tất rotation job cũ của folder trống. Folder có tài liệu phải chờ luồng xoay khóa |

## Xoay khóa tài liệu

Sau khi chạy migration 020, Owner hoặc Editor có envelope nguồn cho mọi phiên bản có thể nhận job trong **Key rotation log**. Trình duyệt giải mã nguồn, tạo DEK mới cho từng phiên bản và gửi bản mã kèm envelope cho thành viên hiện tại. Owner mở nguồn và kết quả để đối chiếu, rồi ký kích hoạt trong lúc lease còn hiệu lực. Nếu lease hết hạn, người xử lý nhận lại job và chuẩn bị kết quả cho generation mới.

Các API xử lý dùng `generation` trên query string. Endpoint `/items` trả recipient JWK và danh sách phiên bản với con trỏ `nextCursor`. Endpoint `/source` và `/result` trả metadata và envelope của người gọi. Để đọc ciphertext, gửi thêm `content=1` và `revisionId` lấy từ metadata. Kết quả stage dùng multipart với hai trường `metadata` và `ciphertext`. Commit nhận chữ ký của Owner trên danh sách kết quả sắp theo `itemId`. Xem luồng ký và định dạng manifest trong `scripts/lib/dev-rotation-client.cjs`.

## Làm lại DB từ đầu

    docker compose down -v && docker compose up -d --wait && npm run migrate && npm run seed

MySQL không rollback được DDL: nếu một migration lỗi giữa chừng, sửa file rồi làm lại DB như trên.

## Tài liệu

- Thiết kế Document Management: `../docs/superpowers/specs/2026-11-23-document-management-design.md`
- Các điểm khác ERD và cần nhóm chốt: `../takenote.md`
