
# coding: utf-8
from multiprocessing import Process, Pipe
from MITM import main as MITM_main
from server import main as server_main
from db_api import *
#from server import main  as server_main


def main():
    MITM_conn, child_conn= Pipe() #create queue for MITM
    MITM_p = Process(target=MITM_main, args=(child_conn,)) #create process for MITM and give the queue as a variable
    MITM_p.start()

    server_conn,child_conn=Pipe() #create pipe for server
    server_p=Process(target=server_main,args=(child_conn,)) #create process for server and give the pipe as a variable
    #server_p.start()

    while True:
        action=server_conn.recv()


        if action == 1: #action: add user
            data=server_conn.recv()
            return_code = add_user(data)
            server_conn.send(return_code)


        elif action == 2: #action: delete user
            data=server_conn.recv()
            return_code=delete_user(data)
            server_conn(return_code)
            #TODO: forward user to remove to MITM (check status code first)

        elif action == 3: #action: add url
            data=server_conn.recv()
            add_url(data)
            #TODO: forward new url to MITM

        elif action == 4: #action: delete url
            data=server_conn.recv()
            delete_url(data)
            #TODO: forward url to delete to MITM

        elif action == 5:
            server_conn.send(get_users_list())

        elif action == 6:
            data=server_conn.recv()
            server_conn.send(get_user(data))

        elif action == 7:
            data=server_conn.recv()
            server_conn.send(get_urls(data))

        elif action == 8:
            data=server_conn.recv()
            update_password(data)

        elif action == 10:
            data=server_conn.recv()
            update_privilege(data)

        elif action == 11:
            server_conn.send(get_admin())

        elif action == 12:
            data=server_conn.recv()
            update_username(data)

        elif action == 13:
            user=server_conn.recv()
            MITM_conn.send(13)
            MITM_conn.send(user)
            MITM_conn.send(get_urls(user[0]))

        elif action == 14:
            user_id = server_conn.recv()
            server_conn.send(get_violations(user_id))
        #TODO: add rest of parser
        #TODO: fix parser (user cases not if statements)




if __name__=="__main__":
    main()
