-- Non-cascading historical references per System ERD sys_note.
CREATE TABLE Audit_Log (
    log_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    actor_id BIGINT UNSIGNED NULL,
    action_type VARCHAR(100) NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    target_id VARCHAR(64) NULL,
    folder_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    document_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    version_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    result ENUM('SUCCESS', 'FAILURE') NOT NULL,
    details JSON NULL,
    ip_address VARCHAR(45) NULL,
    device_id BIGINT UNSIGNED NULL,
    created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (log_id),
    KEY ix_audit_actor_created (actor_id, created_at),
    KEY ix_audit_target (target_type, target_id, created_at),
    KEY ix_audit_action_created (action_type, created_at)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
