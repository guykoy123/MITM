from multiprocessing import Process, Pipe
from MITM import main as MITM_main
from db_api import *
#from server import main  as server_main


def main():
    MITM_conn, child_conn= Pipe() #create queue for MITM
    MITM_p = Process(target=MITM_main, args=(child_conn,)) #create process for MITM and give the queue as a variable

    server_conn,child_conn=Pipe() #create pipe for server
    server_p=Process(target=server_main,args=(child_conn,)) #create process for server and give the pipe as a variable


    while True:
        action=server_conn.recv()
        data=server_conn.recv()

        if action == 1: #action: add user

            return_code = add_user(data)
            server_conn.send(return_code)
            #TODO: add forwarding of new user to MITM (check status code first)

        if action == 2: #action: delete user
            return_code=delete_user(data)
            server_conn(return_code)
            #TODO: add forwarding of user to remove to MITM (check status code first)

        if action == 3: #action: add url
            add_url(data)

        if action == 4: #action: delete url
            delete_url(data)

        #TODO: add rest of parser




if __name__=="__main__":
    main()
