ALTER TABLE User_Key
    ADD COLUMN enrollment_challenge JSON NULL,
    ADD COLUMN enrollment_response_hash CHAR(43) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD COLUMN encrypted_backup JSON NULL;
