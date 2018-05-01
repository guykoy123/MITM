
-- sqlite3


DROP TABLE IF EXISTS users;

CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    password TEXT NOT NULL,
    privilege INTEGER NOT NULL,
    ip TEXT);
    
DROP TABLE IF EXISTS sites;

CREATE TABLE IF NOT EXISTS sites (
    url_id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    user_id INT,
    FOREIGN KEY (user_id) REFERENCES users(user_id));
