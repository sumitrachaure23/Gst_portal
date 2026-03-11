CREATE DATABASE gst_portal;
USE gst_portal;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100) UNIQUE,
    password VARCHAR(255)
);

CREATE TABLE gst_records (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    gst_number VARCHAR(50),
    income FLOAT,
    gst_amount FLOAT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);