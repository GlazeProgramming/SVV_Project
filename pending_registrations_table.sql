CREATE TABLE IF NOT EXISTS pending_registrations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    firstname VARCHAR(100) NOT NULL,
    lastname VARCHAR(100),
    dob DATE NOT NULL,
    phonenumber VARCHAR(100) NOT NULL,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    verification_token VARCHAR(255) NOT NULL,
    token_expires_at DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_token (verification_token),
    INDEX idx_expires (token_expires_at)
);