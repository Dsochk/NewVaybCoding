CREATE DATABASE IF NOT EXISTS todolist;
USE todolist;

CREATE TABLE IF NOT EXISTS items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    text VARCHAR(255) NOT NULL,
    user_id INT NOT NULL,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    login VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    is_admin TINYINT(1) NOT NULL DEFAULT 0,
    role VARCHAR(50) NOT NULL DEFAULT 'user', 
    token VARCHAR(255) DEFAULT NULL
);

INSERT INTO users (login, password, is_admin, role) VALUES ('admin', 'password123', 1, 'admin');
-- Добавляем столбец order_index
ALTER TABLE items ADD COLUMN order_index INT NOT NULL DEFAULT 0;

-- Задаём начальные значения для существующих записей (например, равные ID)
UPDATE items SET order_index = id;
ALTER DATABASE todolist CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
ALTER TABLE items CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
ALTER TABLE users CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;