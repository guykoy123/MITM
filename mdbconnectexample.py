import pyodbc

conn_str = (
    r'DRIVER={Microsoft Access Driver (*.mdb, *.accdb)};'
    r'DBQ=d:\NetworkMonitorData.accdb'
    )
cnxn = pyodbc.connect(conn_str) #connect to database
crsr = cnxn.cursor()

SQL = 'SELECT url FROM blacklist;' # your query goes here
print crsr.execute(SQL).fetchall() #get query response


