import sqlite3
from os import makedirs

try:
    makedirs('../database/')
    
except OSError:
	pass
	
finally:
    with open('../database/test.db','wb') as f:
        pass
	
	conn =sqlite3.connect('../database/test.db')
	
	conn.executescript("""
DROP TABLE IF EXISTS users;

CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    password TEXT NOT NULL,
    privilege INTEGER NOT NULL
);

DROP TABLE IF EXISTS hosts;

CREATE TABLE IF NOT EXISTS hosts (
	host_id INTEGER PRIMARY KEY AUTOINCREMENT,
	mac_addr TEXT NOT NULL,
	privilege INTEGER,
	ignore INTEGER
);

DROP TABLE IF EXISTS sites;

CREATE TABLE IF NOT EXISTS sites (
    url_id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    host_id INT,
    FOREIGN KEY (host_id) REFERENCES hosts(host_id)
);

DROP TABLE IF EXISTS violations;

CREATE TABLE IF NOT EXISTS violations (
    violation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    time_stamp TEXT NOT NULL,
    host_id INT,
    FOREIGN KEY (host_id) REFERENCES hosts(host_id)
);""")

	conn.commit()
	conn.close()
