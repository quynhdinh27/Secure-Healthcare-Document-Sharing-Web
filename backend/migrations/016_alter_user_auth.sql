-- Keep department_id, password_hash, created_by, updated_by NULLable in DDL so
-- scripts/smoke-folder-membership.cjs (INSERT INTO `User` (user_id)) and
-- upstream seed helpers continue to work without modification.
ALTER TABLE `User`
    ADD COLUMN department_id BIGINT UNSIGNED NULL AFTER user_id,
    ADD COLUMN password_hash VARCHAR(255) NULL AFTER email,
    ADD COLUMN created_by BIGINT UNSIGNED NULL AFTER account_status,
    ADD COLUMN updated_by BIGINT UNSIGNED NULL AFTER created_by,
    ADD KEY ix_user_department (department_id),
    ADD KEY ix_user_status_type (account_status, account_type),
    ADD CONSTRAINT fk_user_department
        FOREIGN KEY (department_id) REFERENCES Department (department_id),
    ADD CONSTRAINT fk_user_created_by
        FOREIGN KEY (created_by) REFERENCES `User` (user_id),
    ADD CONSTRAINT fk_user_updated_by
        FOREIGN KEY (updated_by) REFERENCES `User` (user_id);
