CREATE TABLE Folder_Policy_Context (
    context_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    folder_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    owner_membership_id BIGINT UNSIGNED NOT NULL,
    payload JSON NOT NULL,
    expires_at DATETIME(3) NOT NULL,
    consumed_at DATETIME(3) NULL,
    PRIMARY KEY (context_id),
    KEY ix_folder_policy_context_expiry (folder_id, expires_at),
    CONSTRAINT fk_folder_policy_context_folder
        FOREIGN KEY (folder_id) REFERENCES Treatment_Folder (folder_id),
    CONSTRAINT fk_folder_policy_context_owner
        FOREIGN KEY (owner_membership_id) REFERENCES Folder_Membership (membership_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
