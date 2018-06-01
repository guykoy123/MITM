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
from socket import *

# except ImportError:
#
#     #TODO: handle all cases of missing modules and try to solve
#     print 'a module is missing please check you have all required modules'


# global variables:
localAddresses=['192.168.1.11']
addressesLock=Lock()
gatewayMAC=''
user_list=[]
localHost=''
main_conn=Pipe()
defaultGateway=''
active_connections={}

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


def handle_Packet(pkt):
    """
    add sniffed packets to queue of prescanned packets
    if packet is an ARP packet check if new device needs to be added to list
    send it forward
    """
    if ARP not in pkt:
    	if UDP in pkt:
    		#print 'udp packet'
    		if pkt[UDP].dport==53:
    			new_pkt=pkt
    			new_pkt[Ether].dst=gatewayMAC
    			new_pkt[Ether].src="b8:27:eb:fc:2f:ef"
    			new_pkt[IP].src=localHost
    			new_pkt.show()
    			resp= sr1(new_pkt,verbose=0)
    			print resp.summary()
    			return None
    			
			if pkt[UDP].sport==53:
				pkt[Ether].src="b8:27:eb:fc:2f:ef"
				sendp(pkt,verbose=0)
				return None
				
		if TCP in pkt:
			if pkt[TCP].dport==80:
				pkt[Ether].dst=gatewayMAC
				sendp(pkt,verbose=0)
		   		if len(active_connections) ==0:
		   			sendp(pkt,verbose=0)
		   			active_connections[pkt[IP].dst]=[pkt[TCP].sport,long(pkt[TCP].ack)]
		   			print "added"+str((pkt[IP].dst,pkt[TCP].sport))
		   			return 1
		   		    
		   		else:
			   		if pkt[IP].dst not in active_connections.keys():
			   		    sendp(pkt,verbose=0)
			   		    active_connections[pkt[IP].dst]=[pkt[TCP].sport,long(pkt[TCP].ack)]
			   		    print "added"+str((pkt[IP].dst,pkt[TCP].sport))
			   		    return 1
			   		    
			   		elif active_connections[pkt[IP].dst][0]== pkt[TCP].sport:
			   		
				   		if active_connections[pkt[IP].dst][1]<long(pkt[TCP].ack) or 'P' & pkt[TCP].flags:
				   			sendp(pkt,verbose=0)
				   			active_connections[pkt[IP].dst][1]=long(pkt[TCP].ack)
				   			return 1
				   			
				   		elif 'F' & pkt[TCP].flags:
				   			sendp(pkt,verbose=0)
				   			active_connections.pop(pkt[IP].dst,None)
				   			return 1
				   	else:
			   		    print "rejected"+str((pkt[IP].dst,pkt[TCP].sport))
			   		    #TODO: send RST packet
			   		    return 1
		if Ether in pkt:
			if pkt[Ether].dst!="b8:27:eb:fc:2f:ef":
				sendp(pkt,verbose=0)
				#print pkt.summary()
				return None
			   		    
		   		

			   			
			   			
			

    
    #print active_connections
		



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
                if host=='192.168.1.11':
                    #print 'spoofing',host
                    victimPacket =Ether(dst='94:de:80:61:70:52')/ARP(op=2,psrc = router, pdst=host,hwdst='94:de:80:61:70:52')#create arp packets (whdst doesn't matter can be broadcast or specific)
                    #packet needs to have MAC addresses
                    logging.debug('spoofing: '+victimPacket[ARP].pdst)
                    sendp(victimPacket,verbose=0)#send packets
                    
            addressesLock.release()
            sleep(0.5)





def setup():
    """
    get all necessary values for the program to run
    and start all threads
    """
    #get default gateway, local IP address and local MAC address
    global gatewayMAC
    global localHost
    global defaultGateway
    defaultGateway,localHost,gatewayMAC=functions.getLocalhostAddress()
    print defaultGateway,gatewayMAC,localHost
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
    




def main(conn=None):
    """
    control the whole program
    gets the parameters for working
    then calls all functions in order
    """
    #setup logging to file logFile.log
    logging.basicConfig(filename='logFile.log',level=logging.DEBUG, format='%(lineno)s - %(levelname)s : %(message)s')
    logging.info('\n\n\n\n\n########## Program Start ##########\n\n')

    setup() #get all required variables and start all threads
    logging.info('setup complete')

    global main_conn
    main_conn=conn

    sniff(prn=handle_Packet)


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
