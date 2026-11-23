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
