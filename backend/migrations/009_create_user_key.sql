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
