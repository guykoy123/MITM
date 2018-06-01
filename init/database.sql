
-- sqlite3


DROP TABLE IF EXISTS users;

CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    password TEXT NOT NULL,
    privilege INTEGER NOT NULL
);

DROP TABLE IF EXISTS sites;

CREATE TABLE IF NOT EXISTS sites (
    url_id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    user_id INT,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

DROP TABLE IF EXISTS violations;

CREATE TABLE IF NOT EXISTS violations (
    violation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    time_stamp TEXT NOT NULL,
    user_id INT,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);
