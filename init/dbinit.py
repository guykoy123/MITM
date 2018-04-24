import sqlite3


conn =sqlite3.connect('../database/test.db')

conn.execute('''DROP TABLE IF EXISTS users;''')

conn.execute('''CREATE TABLE IF NOT EXISTS users (
  user_id INT PRIMARY KEY,
  name TEXT NOT NULL,
  password TEXT NOT NULL,
  privilege INT);''')

conn.execute('''DROP TABLE IF EXISTS sites;''')

conn.execute('''CREATE TABLE IF NOT EXISTS sites (
  url TEXT NOT NULL,
  user_id INT,
  FOREIGN KEY (user_id) REFERENCES users(user_id));''')

conn.close()
