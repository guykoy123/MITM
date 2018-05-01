import sqlite3
from os import makedirs

try:
    makedirs('../database/')
finally:
    with open('../database/test.db','wb') as f:
        pass

    conn =sqlite3.connect('../database/test.db')

    conn.execute('''DROP TABLE IF EXISTS users;''')

    conn.execute('''CREATE TABLE IF NOT EXISTS users (
      user_id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      password TEXT NOT NULL,
      privilege INTEGER NOT NULL,
      ip TEXT);''')

    conn.execute('''DROP TABLE IF EXISTS sites;''')

    conn.execute('''CREATE TABLE IF NOT EXISTS sites (
      url_id INTEGER PRIMARY KEY AUTOINCREMENT,
      url TEXT NOT NULL,
      user_id INT,
      FOREIGN KEY (user_id) REFERENCES users(user_id));''')

    conn.close()
