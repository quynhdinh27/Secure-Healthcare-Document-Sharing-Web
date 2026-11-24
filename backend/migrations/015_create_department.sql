CREATE TABLE Department (
    department_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    department_code VARCHAR(50) NOT NULL,
    department_name VARCHAR(255) NOT NULL,
    description VARCHAR(1000) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (department_id),
    UNIQUE KEY uq_department_code (department_code),
    UNIQUE KEY uq_department_name (department_name)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4;
