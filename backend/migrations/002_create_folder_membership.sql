-- Run after Treatment_Folder and User. Match user_id, granted_by, revoked_by
-- and active_user_id to the final type and signedness of User.user_id.
CREATE TABLE Folder_Membership (
    membership_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    folder_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    role ENUM('OWNER', 'EDITOR', 'VIEWER') NOT NULL,
    status ENUM('ACTIVE', 'REVOKED') NOT NULL DEFAULT 'ACTIVE',
    granted_by BIGINT UNSIGNED NOT NULL,
    granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_by BIGINT UNSIGNED NULL,
    revoked_at TIMESTAMP NULL DEFAULT NULL,

    -- A NULL generated value leaves revoked rows in the history.
    active_user_id BIGINT UNSIGNED GENERATED ALWAYS AS (
        CASE WHEN status = 'ACTIVE' THEN user_id END
    ) STORED,
    active_owner_marker TINYINT GENERATED ALWAYS AS (
        CASE WHEN status = 'ACTIVE' AND role = 'OWNER' THEN 1 END
    ) STORED,

    PRIMARY KEY (membership_id),
    UNIQUE KEY uq_folder_active_member (folder_id, active_user_id),
    UNIQUE KEY uq_folder_active_owner (folder_id, active_owner_marker),
    KEY ix_folder_membership_user_status (user_id, status, folder_id),
    CONSTRAINT fk_folder_membership_folder
        FOREIGN KEY (folder_id) REFERENCES Treatment_Folder (folder_id),
    CONSTRAINT fk_folder_membership_user
        FOREIGN KEY (user_id) REFERENCES `User` (user_id),
    CONSTRAINT fk_folder_membership_granted_by
        FOREIGN KEY (granted_by) REFERENCES `User` (user_id),
    CONSTRAINT fk_folder_membership_revoked_by
        FOREIGN KEY (revoked_by) REFERENCES `User` (user_id)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
