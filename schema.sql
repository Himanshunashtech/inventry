-- schema.sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    category VARCHAR(50),
    quantity INTEGER DEFAULT 0,
    price DECIMAL(10,2) DEFAULT 0.00,
    created_by INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users (id)
);

-- Insert default super admin
INSERT OR IGNORE INTO users (username, password, email, role) 
VALUES ('admin', 'pbkdf2:sha256:600000$otG2CNUfYjyYU9dK$e1127e1a9f3920fcec65d811dea2f4cb354db7c7aa3b6bdea20984592e7fb7f1', 'admin@inventory.com', 'superadmin');

-- Insert a regular test user
