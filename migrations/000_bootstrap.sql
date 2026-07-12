CREATE DATABASE IF NOT EXISTS auth_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'auth_user'@'%'
    IDENTIFIED BY 'auth_password';

GRANT ALL PRIVILEGES ON auth_db.* TO 'auth_user'@'%';

FLUSH PRIVILEGES;
