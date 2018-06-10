
# coding: utf-8
from multiprocessing import Process, Pipe
from MITM import main as MITM_main
from server import main as server_main
from db_api import *
import logging



def main():
	#setup logging to file logFile.log
    logging.basicConfig(filename='netmon_log.log',level=logging.DEBUG, format='%(lineno)s - %(levelname)s : %(message)s')
    
    MITM_conn, child_conn= Pipe() #create pipe for MITM
    MITM_p = Process(target=MITM_main, args=(child_conn,)) #create process for MITM and give the queue as a variable
    #MITM_p.start()
	logging.info('MITM started')

    server_conn,child_conn=Pipe() #create pipe for server
    server_p=Process(target=server_main,args=(child_conn,)) #create process for server and give the pipe as a variable
    server_p.start()
    logging.info('server started')
    
    while True:
        action=server_conn.recv()
		
		if action ==1: #action: add user
			data=server_conn.recv()
			MITM_conn.send(1)
			MITM_conn.send(data)
			logging.debug('user added'+str(data))
			
        elif action == 2: #action: delete user
            data=server_conn.recv()
            return_code=delete_user(data)
            server_conn(return_code)
            MITM_conn.send(2)
            MITM_conn.send(data)
			logging.debug('user deleted'+ str(data))

        elif action == 3: #action: add url
            data=server_conn.recv()
            add_url(data)
            MITM_conn.send(3)
            MITM_conn.send(data[1])
            logging.debug('url added '+str(data))
            

        elif action == 4: #action: delete url
            data=server_conn.recv()
            delete_url(data)
            MITM_conn.send(4)
            MITM_conn.send(data)
            logging.debug('url deleted '+str(data))


        elif action == 5: #action: get users list
            server_conn.send(get_users_list())


        elif action == 6: #action: get user
            data=server_conn.recv()
            server_conn.send(get_user(data))


        elif action == 7: #action: get urls list for user
            data=server_conn.recv()
            server_conn.send(get_urls(data))

        elif action == 8: #actions: update password
            data=server_conn.recv()
            update_password(data)
            logging.debug('updated password')

        elif action == 10: #action: update privilege
            data=server_conn.recv()
            update_privilege(data)
			MITM_conn.send(10)
			MITM_conn.send(data)
			logging.debug('updated privilege ' +str(data))
					
        elif action == 11: #action: get admin
            server_conn.send(get_admin())
           

        elif action == 12: #action: update username
            data=server_conn.recv()
            update_username(data)
            logging.debug('updated username')

        elif action == 13: #action: get violations
            user_id = server_conn.recv()
            server_conn.send(get_violations(user_id))

            
        #TODO: add rest of parser
        #TODO: fix parser (user cases not if statements)"""




if __name__=="__main__":
    main()
