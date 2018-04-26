import sqlite3

conn =sqlite3.connect('../database/test.db')

#add sample users to database
conn.execute('''INSERT INTO users (name,password,privilege) VALUES ("dan","asdf",1);''')
conn.execute('''INSERT INTO users (name,password,privilege) VALUES ("david","ghjk",2);''')
conn.execute('''INSERT INTO users (name,password,privilege) VALUES ("shit","py",2);''')
conn.execute('''INSERT INTO users (name,password,privilege) VALUES ("david","sdfg",2);''')

conn.commit()

conn.close()
