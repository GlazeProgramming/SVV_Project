CREATE DATABASE userdb;
USE userdb;
 /*
SELECT * FROM USERS;
DROP TABLE users;
*/
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    firstname VARCHAR(100) NOT NULL,
    lastname VARCHAR(100),
    dob DATE NOT NULL,
    phonenumber VARCHAR(100) NOT NULL,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    verification_token VARCHAR(255),
    is_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

DROP USER IF EXISTS 'svvuser'@'localhost';
CREATE USER 'svvuser'@'localhost' IDENTIFIED BY 'svv123';
GRANT ALL PRIVILEGES ON userdb.* TO 'svvuser'@'localhost';
FLUSH PRIVILEGES;



