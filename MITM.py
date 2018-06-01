#python 2.7

from multiprocessing import Pipe
import logging
from threading import Thread,Lock
from time import sleep
from scapy.all import *
from datetime import datetime
import functions
from sys import exit
from user import *


# except ImportError:
#
#     #TODO: handle all cases of missing modules and try to solve
#     print 'a module is missing please check you have all required modules'


# global variables:
localAddresses=['192.168.1.29']
addressesLock=Lock()
gatewayMAC='94:de:80:61:70:52'
bad_packet=[]
user_list=[]
localHost='192.168.1.11'
main_conn=Pipe()
defaultGateway='192.168.1.1'


def blocked(user,url):
    """
    return True if site is blocked for user
    """
    if user.get_privilege() == 0: #admin can access all sites
        return False

    if user.get_privilege() == 1: #blacklist user
        for l_url in user.url_list:
            if l_url[1] == url:
                return True
        return False

    for l_url in user.get_url_list(): #whitelist user
        if l_url[1] == url:
            return False
    return True



def arpSpoof(router):
    """
    every 30 seconds send ARP broadcast to spoof all machines on LAN
    """
    print 'router:',router
    while True:

        if len(localAddresses)>0:
            addressesLock.acquire()
            #print 'spoofing',str(len(localAddresses)), localAddresses
            for host in localAddresses :
                #if host != localHost:
                if host=='192.168.1.29':
                    victimPacket =Ether(dst='8c:70:5a:84:68:20')/ARP(op=2,psrc = router, pdst=host,hwdst='8c:70:5a:84:68:20')#create arp packets (whdst doesn't matter can be broadcast or specific)
                    logging.debug('spoofing: '+victimPacket[ARP].pdst)
                    sendp(victimPacket,verbose=0)#send packets
            addressesLock.release()







def setup():
    """
    get all necessary values for the program to run
    and start all threads
    """
    #get default gateway, local IP address and local MAC address
    #defaultGateway,localHost,gatewayMAC=functions.getLocalhostAddress()
    #print defaultGateway,gatewayMAC,localHost
    logging.debug('got default gateway and local IP and MAC')

    global localAddresses
    #TODO: retrieve MAC addresses as well as IP addresses
    #localAddresses=functions.get_Local_Addresses(defaultGateway,localHost) #get addresses of all hosts on network
    logging.debug('scanned network for all active hosts')
    print localAddresses

    arpThread=Thread(target=arpSpoof,args=(defaultGateway,))
    logging.debug('created thread for ARP spoofing')
    arpThread.start()
    logging.debug('spoofing all hosts on network')

    proxyThread=Thread(target=proxy)
    proxyThread.start()


def main(conn):
    """
    control the whole program
    gets the parameters for working
    then calls all functions in order
    """
    #setup logging to file logFile.log
    logging.basicConfig(filename='logFile.log',level=logging.INFO, format='%(lineno)s - %(levelname)s : %(message)s')
    logging.info('\n\n\n\n\n########## Program Start ##########\n\n')

    setup() #get all required variables and start all threads
    logging.info('setup complete')

    global main_conn
    main_conn=conn

    #sniff(prn=handle_Packet)


    while True:
        command=main_conn.recv()

        if command==13:
            user=main_conn.recv()
            url_list=main_conn.recv()
            user_list.append(User(user[0],user[1],user[2],url_list))
            logging.info('New user connected'+user[0])
            print "user connected",user[0]



    #TODO: add queue to communicate to main program to update changing information for each user for example :ip address, privilege, url list



if __name__=='__main__':
    main()
