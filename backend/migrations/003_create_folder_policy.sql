CREATE TABLE Folder_Policy (
    folder_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    policy_version INT UNSIGNED NOT NULL,
    signed_policy JSON NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (folder_id, policy_version),
    CONSTRAINT fk_folder_policy_folder
        FOREIGN KEY (folder_id) REFERENCES Treatment_Folder (folder_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
