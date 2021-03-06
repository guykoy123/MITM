import sqlite3

database='database/test.db'


def delete_user(data):
    """
    remove user from database if data is valid
    """

    conn = sqlite3.connect(database) #connect to database
    conn.execute('''DELETE FROM hosts WHERE host_id = %d;''' % (int(data))) #delete the url
    conn.commit() #save changes
    conn.close()

def add_url(data):
    """
    adds url to url list
    """

    conn=sqlite3.connect(database) #connect to database
    conn.execute('''INSERT INTO sites (url,host_id) VALUES ("%s",%d);''' % (data[0],int(data[1])))#insert new url to sites table
    conn.commit()#save changes
    conn.close()

def delete_url(data):
    """
    delete url from sites list
    """

    conn=sqlite3.connect(database)#connect to database
    conn.execute('''DELETE FROM sites WHERE url_id = %d;''' % (int(data))) #delete url from sites table
    conn.commit() #save changes
    conn.close()

def update_password(data):
    """
    update password for user
    """
    conn=sqlite3.connect(database)
    conn.execute('''UPDATE users SET password = "%s" WHERE user_id = %d;'''%(data[1],int(data[0])))
    conn.commit()
    conn.close()

def get_users_list():
    """
    return list of all MACs and their ids
    """

    conn=sqlite3.connect(database) #connect to database
    cursor=conn.execute('''SELECT mac_addr, host_id FROM hosts WHERE ignore=2;''') #retrieve all username and user ids except admin user
    hosts=list()
    for row in cursor:
        hosts.append(row)
    conn.close()
    return hosts

def get_user(data):
    """
    return user (name, password, privilege)
    """

    conn=sqlite3.connect(database)#connect to database
    cursor=conn.execute('''SELECT mac_addr, privilege, ignore FROM hosts WHERE host_id = %d;''' % (int(data)))#retrieve data about user
    for row in cursor:
        return row

def get_urls(data):
    """
    returns all urls for a user
    """

    conn=sqlite3.connect(database)
    cursor=conn.execute('''SELECT url_id, url FROM sites WHERE host_id = %d;''' % (int(data)))
    url_list=list()
    for row in cursor:
        url_list.append(row)
    return url_list


def update_privilege(data):
    """
    updates privilege of users
    """
    conn=sqlite3.connect(database) #connect to database
    conn.execute('''UPDATE hosts SET privilege = %d WHERE host_id=%d;'''%(int(data[1]),int(data[0]))) #update privilege
    conn.commit()#commit changes
    conn.close()


def update_username(data):
    """
    updates username of a user
    """
    conn=sqlite3.connect(database)
    conn.execute('''UPDATE users SET name = "%s" WHERE user_id=%d;'''%(data[1],int(data[0])))
    conn.commit()
    conn.close()

def get_admin():
    """
    return admin id, username and password
    """

    conn=sqlite3.connect(database) #connect to database
    cursor=conn.execute('''SELECT user_id, name, password FROM users WHERE privilege=0;''')
    admin=None
    for row in cursor:
        admin=row
    conn.close()
    return admin


def get_violations(data):
    """
    returns violations for specific user
    """

    conn=sqlite3.connect(database)
    cursor=conn.execute('''SELECT time_stamp, url FROM violations where host_id=%d'''%(int(data)) )
    violations=[]
    for row in cursor: #TODO: add check if recent
        violations.append(row)
    return violations


def add_new_hosts(addresses):

	conn=sqlite3.connect(database)
	cursor=conn.execute('''SELECT mac_addr FROM hosts''')
	mac_addrss=[]
	for row in cursor:
		mac_addrss.append(row[0])
	
	for host in addresses.values(): #check that host mac
		add=True
		for mac in mac_addrss:
			if host == str(mac): #is not in the existing list
				add=False
		if add:
			conn.execute('''INSERT INTO hosts (mac_addr,ignore) VALUES ("{}",0)'''.format(host))

	conn.commit()
	conn.close()

def add_violation(data):
	conn=sqlite3.connect(database)
	conn.execute('''INSERT INTO violations (host_id,url,time_stamp) VALUES ("{}","{}","{}");'''.format(data[0],data[1],data[2]))
	conn.commit()
	conn.close()

def get_new_hosts():
    conn=sqlite3.connect(database)
    cursor=conn.execute('''SELECT mac_addr,host_id FROM hosts WHERE ignore = 0;''')
    new_hosts=[]
    for row in cursor:
        new_hosts.append(row)
    conn.close()
    return new_hosts

def update_ignore(data):
    conn=sqlite3.connect(database)
    conn.execute('''UPDATE hosts SET ignore = {} WHERE host_id="{}"'''.format(data[1],data[0]))
    conn.commit()
    conn.close()

def get_ignored():
    conn=sqlite3.connect(database)
    cursor=conn.execute('''SELECT mac_addr,host_id FROM hosts WHERE ignore=1;''')
    ignored=[]
    for row in cursor:
        ignored.append(row)
    conn.close()
    return ignored
