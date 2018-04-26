import sqlite3

database='database/test.db'
#TODO: add function to update the database

def add_user(data):
    """
    adds new user to database if not exists and data is invalid
    return codes:
    0: successfuly added
    1: user already exists
    2: invalid database
    """

    #check for invalid data to prevent errors
    if type(data) != list:
        return 2
    if type(data[0]) != str:
        return 2
    if type(data[1]) != str:
        return 2
    if type(data[2]) != int:
        return 2
    if data[2]>3 or data[2]<0:
        return 2


    conn=sqlite3.connect(database) #connect to database

    cursor = conn.execute(''' SELECT name, password FROM users;''') #retrieve name and passwords
    for row in cursor:
        if row[0] == data[0] and row[1] == data[1]: #check if the user already exists
            conn.close()
            return 1 #if exists do not add and return code: 1


    #insert the new user to the database
    query =('''INSERT INTO users (name, password, privilege) VALUES ("%s","%s",%d);''' % (data[0],data[1],data[2]))
    conn.execute(query)
    conn.commit() #commit changes
    conn.close()
    return 0 #return successful code:0

def delete_user(data):
    """
    remove user from database if data is valid
    return codes:
    0: successfuly removed
    2: invalid database
    """

    #check data validity
    if type(data) != int:
        return 2
    if data<=0:
        return 2

    conn = sqlite3.connect(database)
    conn.execute('''DELETE FROM users WHERE user_id = %d;''' % (data) )
    conn.commit()
    conn.close()
    return 0

#TODO:  add rest of functions

def main():
    pass


if __name__ =="__main__":
    main()
