CREATE TABLE User_Session (
    session_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    csrf_token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    reauthenticated_at TIMESTAMP(3) NULL DEFAULT NULL,
    expires_at TIMESTAMP(3) NOT NULL,
    revoked_at TIMESTAMP(3) NULL DEFAULT NULL,
    revoke_reason VARCHAR(64) NULL,
    ip_address VARCHAR(45) NULL,
    user_agent VARCHAR(255) NULL,
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_seen_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (session_id),
    UNIQUE KEY uq_user_session_token_hash (token_hash),
    KEY ix_user_session_user_active (user_id, revoked_at, expires_at),
    CONSTRAINT fk_user_session_user
        FOREIGN KEY (user_id) REFERENCES `User` (user_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
