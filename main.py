from multiprocessing import Process,Queue
import MITM.main
import server.main

#TODO: add function to update the database

def add_user(data):
    pass

def delete_user(data):
    pass





def main():
    MITM_conn= Queue()
    MITM_p = Process(target=MITM.main, args=(MITM_conn,))
    server_conn=Queue()
    server_p=Process(target=server.main,args=(server_conn,))
    while True:
        action=server_conn.get()
        data=server_conn.get()
        if action == 1: #action: add user
            add_user(data)
        if action == 2: #action: delete user
            delete_user(data)
        if action == 3: #action: add url
            add_url(data)
        if action == 4: #action: delete url
            delete_url(data)

        #TODO: add parser
        #TODO: perform action

    pass


if __name__=="__main__":
    main()
