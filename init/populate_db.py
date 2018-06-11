import sqlite3

conn =sqlite3.connect('../database/test.db')

#add admin to database
conn.execute('''INSERT INTO users (name,password,privilege) VALUES ("admin","admin",0);''')

#add sample hosts
conn.execute('''INSERT INTO hosts (mac_addr,privilege,ignore) VALUES ("94:de:80:61:70:52",1,2);''')
conn.execute('''INSERT INTO hosts (mac_addr,privilege,ignore) VALUES ("94:de:80:61:60:ff",1,2);''')
conn.execute('''INSERT INTO hosts (mac_addr,ignore) VALUES ("28:d2:44:0b:ef:ab",0);''')
conn.execute('''INSERT INTO hosts (mac_addr,ignore) VALUES ("28:d2:f4:0b:ef:e9",0);''')


#add sample sites to database
conn.execute('''INSERT INTO sites (url,host_id) VALUES ("html.net",1);''')
conn.execute('''INSERT INTO sites (url,host_id) VALUES ("www.youtube.com",1);''')
conn.execute('''INSERT INTO sites (url,host_id) VALUES ("www.facebook.com",1);''')

#TODO: add sample violations
conn.commit()

conn.close()
