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
