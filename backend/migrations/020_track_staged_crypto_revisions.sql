ALTER TABLE Crypto_Revision
    ADD COLUMN rotation_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD COLUMN rotation_generation INT UNSIGNED NULL,
    ADD UNIQUE KEY uq_rotation_generation_version (rotation_id, rotation_generation, version_id),
    ADD CONSTRAINT fk_revision_rotation
        FOREIGN KEY (rotation_id) REFERENCES Folder_Rotation_Job (rotation_id),
    ADD CONSTRAINT chk_revision_rotation_generation CHECK (
        (rotation_id IS NULL AND rotation_generation IS NULL) OR
        (rotation_id IS NOT NULL AND rotation_generation IS NOT NULL AND rotation_generation > 0)
    );
