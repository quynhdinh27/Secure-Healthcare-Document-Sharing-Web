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
