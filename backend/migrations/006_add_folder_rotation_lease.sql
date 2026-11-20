ALTER TABLE Folder_Rotation_Job
    ADD COLUMN generation INT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN executor_id BIGINT UNSIGNED NULL,
    ADD COLUMN lease_expires_at DATETIME(3) NULL,
    ADD CONSTRAINT fk_folder_rotation_executor
        FOREIGN KEY (executor_id) REFERENCES `User` (user_id);
