-- One encrypted ciphertext per business version per rotation. The 16-byte GCM tag
-- is appended to the ciphertext (WebCrypto output), so there is no tag column.
CREATE TABLE Crypto_Revision (
    revision_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    version_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    revision_number INT UNSIGNED NOT NULL,
    status ENUM('STAGED', 'ACTIVE', 'SUPERSEDED') NOT NULL,
    active_marker TINYINT GENERATED ALWAYS AS (
        CASE WHEN status = 'ACTIVE' THEN 1 END
    ) STORED,
    storage_object_key VARCHAR(80) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    ciphertext_size BIGINT UNSIGNED NOT NULL,
    ciphertext_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    aead_algorithm VARCHAR(16) NOT NULL DEFAULT 'AES-256-GCM',
    nonce VARBINARY(12) NOT NULL,
    policy_version INT UNSIGNED NOT NULL,
    signed_manifest JSON NOT NULL,
    signer_key_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_by BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    activated_at DATETIME(3) NULL,
    PRIMARY KEY (revision_id),
    UNIQUE KEY uq_revision_number (version_id, revision_number),
    UNIQUE KEY uq_revision_active (version_id, active_marker),
    UNIQUE KEY uq_revision_object (storage_object_key),
    CONSTRAINT fk_revision_version FOREIGN KEY (version_id) REFERENCES Document_Version (version_id),
    CONSTRAINT fk_revision_signer_key FOREIGN KEY (signer_key_id) REFERENCES User_Key (key_id),
    CONSTRAINT fk_revision_creator FOREIGN KEY (created_by) REFERENCES `User` (user_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
