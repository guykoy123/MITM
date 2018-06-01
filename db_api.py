import sqlite3

database='database/test.db'
#TODO: add function to update the database

def add_user(data):
    """
    adds new user to database if not exists
    when successful return new user id

    return codes:
    1: user already exists
    """

    conn=sqlite3.connect(database) #connect to database

    cursor = conn.execute(''' SELECT name, password FROM users;''') #retrieve name and passwords
    for row in cursor:
        if row[0] == data[0] and row[1] == data[1]: #check if the user already exists
            conn.close()
            return 1 #if exists do not add and return code: 1

    #insert the new user to the database
    query =('''INSERT INTO users (name, password, privilege) VALUES ("%s","%s",%d);''' % (data[0],data[1],int(data[2])))
    conn.execute(query)
    conn.commit() #commit changes
    cursor=conn.execute('''SELECT user_id FROM users WHERE name = "%s";''' % (data[0])) #get the new user id


    for row in cursor:
        user_id=row
    conn.close()
    new_user=list(user_id).append(int(data[2])) #return new user for MITM
    return new_user

def delete_user(data):
    """
    remove user from database if data is valid
    """

    conn = sqlite3.connect(database) #connect to database
    conn.execute('''DELETE FROM users WHERE user_id = %d;''' % (int(data))) #delete the url
    conn.commit() #save changes
    conn.close()

def add_url(data):
    """
    adds url to url list
    """

    conn=sqlite3.connect(database) #connect to database
    conn.execute('''INSERT INTO sites (url,user_id) VALUES ("%s",%d);''' % (data[0],int(data[1])))#insert new url to sites table
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
    return list of all usernames and their ids
    except the admin
    """

    conn=sqlite3.connect(database) #connect to database
    cursor=conn.execute('''SELECT name, user_id FROM users WHERE privilege != 0;''') #retrieve all username and user ids except admin user
    users=list()
    for row in cursor:
        users.append(row)
    conn.close()
    return users

def get_user(data):
    """
    return user (name, password, privilege)
    """

    conn=sqlite3.connect(database)#connect to database
    cursor=conn.execute('''SELECT name, password, privilege FROM users WHERE user_id = %d;''' % (int(data)))#retrieve data about user
    for row in cursor:
        return row

def get_urls(data):
    """
    returns all urls for a user
    """

    conn=sqlite3.connect(database)
    cursor=conn.execute('''SELECT url_id, url FROM sites WHERE user_id = %d;''' % (int(data)))
    url_list=list()
    for row in cursor:
        url_list.append(row)
    return url_list

def update_ip(data):
    """
    updates user ip address
    """
    conn=sqlite3.connect(database) #connect to database
    conn.execute('''UPDATE users SET ip = "%s" WHERE user_id = %d;''' % (data[1],int(data[0])))#update ip address
    conn.commit()#commit changes
    conn.close() #close connection

def update_privilege(data):
    """
    updates privilege of users
    """
    conn=sqlite3.connect(database) #connect to database
    conn.execute('''UPDATE users SET privilege = %d WHERE user_id=%d;'''%(int(data[1]),int(data[0]))) #update privilege
    conn.commit()#commit changes
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

def update_username(data):
    """
    updates username of a user
    """
    conn=sqlite3.connect(database)
    conn.execute('''UPDATE users SET name = "%s" WHERE user_id=%d;'''%(data[1],int(data[0])))
    conn.commit()
    conn.close()

def get_violations(data):
    """
    returns violations for specific user
    """

    conn=sqlite3.connect(database)
    cursor=conn.execute('''SELECT time_stamp, url FROM violations where user_id=%d'''%(data) )
    violations=[]
    for row in cursor: #TODO: add check if recent
        violations.append(row)
    return Violations

def main():
    pass


if __name__ =="__main__":
    main()
