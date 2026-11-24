-- Business versions (V1, V2...). Rows are never updated; crypto data lives in Crypto_Revision.
CREATE TABLE Document_Version (
    version_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    document_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    version_number INT UNSIGNED NOT NULL,
    base_version_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    created_by BIGINT UNSIGNED NOT NULL,
    author_key_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    mime_type VARCHAR(127) NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (version_id),
    UNIQUE KEY uq_document_version_number (document_id, version_number),
    CONSTRAINT fk_version_document FOREIGN KEY (document_id) REFERENCES Document (document_id),
    CONSTRAINT fk_version_base FOREIGN KEY (base_version_id) REFERENCES Document_Version (version_id),
    CONSTRAINT fk_version_creator FOREIGN KEY (created_by) REFERENCES `User` (user_id),
    CONSTRAINT fk_version_author_key FOREIGN KEY (author_key_id) REFERENCES User_Key (key_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;

ALTER TABLE Document
    ADD CONSTRAINT fk_document_current_version
        FOREIGN KEY (current_version_id) REFERENCES Document_Version (version_id);
