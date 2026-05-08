-- seed.sql — Lab database initialization
-- WARNING: Contains intentionally weak credentials for educational use

CREATE DATABASE IF NOT EXISTS labdb;
USE labdb;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,   -- Stored in plaintext (intentionally insecure)
    email VARCHAR(100),
    role ENUM('admin','user') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sensitive_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    data_type VARCHAR(50),
    value TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    token VARCHAR(255),
    expires_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Seed data (intentionally weak passwords for lab)
INSERT INTO users (username, password, email, role) VALUES
    ('admin', 'password123', 'admin@lab.local', 'admin'),
    ('victim', 'letmein', 'victim@lab.local', 'user'),
    ('john.doe', 'qwerty', 'john@lab.local', 'user'),
    ('jane.doe', '123456', 'jane@lab.local', 'user'),
    ('svc_account', 'Service!1', 'svc@lab.local', 'user');

INSERT INTO sensitive_data (user_id, data_type, value) VALUES
    (1, 'api_key', 'LAB-API-KEY-FLAG{database_exfil_demo}'),
    (1, 'internal_note', 'Admin credentials: admin/password123'),
    (2, 'personal', 'SSN: 000-00-0000 (FAKE LAB DATA)');

-- Weak service account for lateral movement demo
CREATE USER IF NOT EXISTS 'svc_backup'@'%' IDENTIFIED BY 'backup123';
GRANT SELECT ON labdb.* TO 'svc_backup'@'%';
