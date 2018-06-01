import sqlite3

conn =sqlite3.connect('../database/test.db')

#add sample users to database
conn.execute('''INSERT INTO users (name,password,privilege) VALUES ("admin","admin",0);''')
conn.execute('''INSERT INTO users (name,password,privilege) VALUES ("dan","asdf",1);''')
conn.execute('''INSERT INTO users (name,password,privilege) VALUES ("david","ghjk",2);''')
conn.execute('''INSERT INTO users (name,password,privilege) VALUES ("shit","py",2);''')
conn.execute('''INSERT INTO users (name,password,privilege) VALUES ("david","sdfg",2);''')

#add sanmple sites to database
conn.execute('''INSERT INTO sites (url,user_id) VALUES ("www.facebook.com",2);''')
conn.execute('''INSERT INTO sites (url,user_id) VALUES ("www.youtube.com",2);''')
conn.execute('''INSERT INTO sites (url,user_id) VALUES ("www.facebook.com",1);''')
conn.execute('''INSERT INTO sites (url,user_id) VALUES ("www.pornhub.com",3);''')
conn.execute('''INSERT INTO sites (url,user_id) VALUES ("www.shit.com",4);''')

#TODO: add sample violations
conn.commit()

conn.close()
