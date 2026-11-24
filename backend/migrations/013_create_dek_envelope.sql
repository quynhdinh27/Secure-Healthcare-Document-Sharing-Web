-- RSA-OAEP-3072 wrapped DEK per crypto revision and recipient (System design 6, 11).
CREATE TABLE DEK_Envelope (
    envelope_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    revision_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    recipient_user_id BIGINT UNSIGNED NOT NULL,
    recipient_membership_id BIGINT UNSIGNED NOT NULL,
    recipient_key_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    wrapped_dek VARBINARY(512) NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (envelope_id),
    UNIQUE KEY uq_envelope_revision_recipient (revision_id, recipient_user_id),
    KEY ix_envelope_recipient (recipient_user_id, revision_id),
    CONSTRAINT fk_envelope_revision FOREIGN KEY (revision_id) REFERENCES Crypto_Revision (revision_id),
    CONSTRAINT fk_envelope_user FOREIGN KEY (recipient_user_id) REFERENCES `User` (user_id),
    CONSTRAINT fk_envelope_membership
        FOREIGN KEY (recipient_membership_id) REFERENCES Folder_Membership (membership_id),
    CONSTRAINT fk_envelope_key FOREIGN KEY (recipient_key_id) REFERENCES User_Key (key_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
