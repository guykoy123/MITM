#python 2.7

from multiprocessing import Pipe,Process
import logging
from threading import Thread,Lock
from time import sleep
from scapy.all import *
from datetime import datetime
import functions
from sys import exit,stdin
from user import *
from os import system
import subprocess

# except ImportError:
#
#     #TODO: handle all cases of missing modules and try to solve
#     print 'a module is missing please check you have all required modules'


# global variables:
localAddresses=[]
addressesLock=Lock()
gatewayMAC=''
user_list=[]
localHost=''
main_conn=Pipe()
defaultGateway=''


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

def handle_packet(pkt):
	"""
	detects http packets and extracts urls to save in the database
	"""

	if ARP in pkt:
		if pkt[ARP].op == 2: #check if ARP operation is: is-at
			address=pkt[ARP].psrc #extract IP address
			addressesLock.acquire()
			global localAddresses
			global defaultGateway
			global localHost
			if address not in localAddresses.keys() and address != defaultGateway and address!=localHost: #check for duplicates and not default gateway or local host
				localAddresses[address]=pkt[Ether].src #add IP  and MAC address to dict of all hosts
				logging.info('added: {}'.format(address))
			addressesLock.release()
		
        
def spoof(target,defaultGateway):
	"""
	arp spoofs specific ip address
	utilizes arpspoof package
	"""
	system('arpspoof -i eth0 -t {} {}'.format(target,defaultGateway)) #-i [interface] -t [target] [gateway]
	
def arp_spoof(defaultGateway):
	"""
	creates threads for spoofing each host on network
	"""
	threads={}
	while True:
		for target in localAddresses.keys():
			if target not in threads.keys():
				s=Thread(target=spoof,args=(target,defaultGateway,)) #thread for spoofing target
				s.start()
				s2=Thread(target=spoof,args=(defaultGateway,target)) #thread for spoofing router
				s2.start()
				threads[target]=[s,s2]
				logging.debug('spoofing:'+target)
	logging.info('spoofing al hosts')
		
		
def setup():
    """
    get all necessary values for the program to run
    and start all threads
    """
    #get default gateway, local IP address and local MAC address
    defaultGateway,localHost,gatewayMAC=functions.getLocalhostAddress()
    print defaultGateway,gatewayMAC,localHost

	#get addresses of all hosts on network
    global localAddresses
    localAddresses=functions.get_Local_Addresses(defaultGateway,localHost) 
    if defaultGateway in localAddresses.keys():
    	del localAddresses[defaultGateway] #remove default gateway from address dict to prevent unneccery spoofing etc.
    	logging.debug('removed default gateway from local addresses list')
    logging.info('scanned network for all active hosts')
    print localAddresses
	
	#create process for spoofing all hosts on network
    arpThread=Process(target=arp_spoof,args=(defaultGateway,))
    logging.info('created process for ARP spoofing')
    #arpThread.start()
    
    target='192.168.1.33'
    s=Thread(target=spoof,args=(target,defaultGateway,)) #thread for spoofing target
    s.start()
    s2=Thread(target=spoof,args=(defaultGateway,target)) #thread for spoofing router
    s2.start()
				
    #turn ip forwarding on
    system('sysctl -w net.ipv4.ip_forward=1')
    logging.info('ip forwarding enabled')



def main(conn=None):
    """
    control the whole program
    gets the parameters for working
    then calls all functions in order
    """
    #setup logging to file logFile.log
    logging.basicConfig(filename='logFile.log',level=logging.DEBUG, format='%(lineno)s - %(levelname)s : %(message)s')
    logging.info('\n\n\n\n\n########## Program Start ##########\n\n')

	#get all required variables and start all threads
    setup() 
    logging.info('setup complete')
    
    sniff(prn=handle_packet)
	
    global main_conn
    main_conn=conn
    
    system('urlsnarf > sniff.txt')
    	
    """while True:
        command=main_conn.recv()

        if command==13:
            user=main_conn.recv()
            url_list=main_conn.recv()
            user_list.append(User(user[0],user[1],user[2],url_list))
            logging.info('New user connected'+user[0])
            print "user connected",user[0]"""



    #TODO: add queue to communicate to main program to update changing information for each user for example :ip address, privilege, url list



if __name__=='__main__':
    main()
