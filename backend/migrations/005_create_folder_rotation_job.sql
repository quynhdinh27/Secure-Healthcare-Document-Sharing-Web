CREATE TABLE Folder_Rotation_Job (
    rotation_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    folder_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    policy_version INT UNSIGNED NOT NULL,
    requested_by BIGINT UNSIGNED NOT NULL,
    action ENUM('ADD_MEMBER', 'CHANGE_ROLE', 'REVOKE_MEMBER') NOT NULL,
    status ENUM(
        'PENDING', 'IN_PROGRESS', 'WAITING_FOR_CLIENT', 'WAITING_FOR_KEY',
        'WAITING_FOR_OWNER', 'COMPLETED', 'FAILED', 'CANCELLED'
    ) NOT NULL DEFAULT 'PENDING',
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    finished_at DATETIME(3) NULL,
    PRIMARY KEY (rotation_id),
    UNIQUE KEY uq_folder_rotation_policy (folder_id, policy_version),
    KEY ix_folder_rotation_status (folder_id, status),
    CONSTRAINT fk_folder_rotation_policy
        FOREIGN KEY (folder_id, policy_version) REFERENCES Folder_Policy (folder_id, policy_version),
    CONSTRAINT fk_folder_rotation_requester
        FOREIGN KEY (requested_by) REFERENCES `User` (user_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
