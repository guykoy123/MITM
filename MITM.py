#python 2.7

from multiprocessing import Pipe,Process, Queue
import logging
from threading import Thread,Lock
from time import sleep,strftime
from scapy.all import *
import functions
from sys import exit,stdin
from user import *
from os import system
from subprocess import Popen,PIPE
from urlparse import urlparse
from db_api import *
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
			if pkt[Ether].dst!="______": #add host MAC address
				sendp(pkt,verbose=0)
				#print pkt.summary()
				return None
			   		    
#-------------old code---------------		   		
    """url=None
    if ARP not in pkt:
        if TCP in pkt:
            if 80 == pkt[TCP].dport: #check if packet is http packet
                if Raw in pkt:
                    if "GET" in pkt[Raw]:
                        logging.debug("HTTP:"+ pkt.summary())
                        functions.redirect_to_login(pkt,gatewayMAC)
                        pkt.show()
                    else:
                        functions.sendPacket(pkt,gatewayMAC)
                else:
                    functions.sendPacket(pkt,gatewayMAC)
                try:
                    if Raw in pkt:
                        fields=str(pkt[Raw]).split('\r\n') #split into packet fields
                        for field in fields:
                            if 'Host:' == field[:5]:        #if Host field exctract url
                                url=field[5:]
                                break
                        if (url != None):
                            logging.info("URL:"+url)
                            ip=pkt[IP].src
                            logging.info('IP:'+ip)
                            new_user=True
                            if len(user_list) ==0:
                                functions.redirect_to_login(pkt)
                            else:
                                for user in user_list:
                                    if ip == user.get_ip():
                                        new_user=False
                                    if "networkmanager" in url or localHost in url: #check if requesting for network manager
                                            pass
                                    else:
                                        if not blocked(user,url):
                                            #functions.sendPacket(pkt,gatewayMAC)
                                        else:
                                            loggin.info('%s blocked for %s' %(url,ip))
                                            #TODO: return page is blocked
                                if new_user:
                                    logging.info('redirecting %s to login (new user)' % (ip))
                                    functions.redirect_to_login(pkt)
                                    pkt.show()
                        else:
                            logging.warning('url field not found') #save packets that cause errors
                            wrpcap('error.pcap',pkt)
                except Exception as exc:
                    print exc
                    #logging.warning(str(exc)," : ",pkt.summary())
    else:
        if pkt[ARP].op == 2: #check if ARP operation is: is-at
            address=pkt[ARP].psrc #extract IP address
            addressesLock.acquire()
            global localAddresses
            if address not in localAddresses and address != defaultGateway and address!=localHost: #check for duplicates and not default gateway or local host
                localAddresses.append(address) #add IP address to list of all hosts
                print 'added',address
            addressesLock.release()"""
			   			
			   			
			

    
    #print active_connections


def blocked(user,url):
	"""
	return True if site is blocked for user
	"""
	if user.get_privilege() == 1: #blacklist user
		for l_url in user.url_list:
			if l_url[1] == url:
		   		return True
		return False

	for l_url in user.get_url_list(): #whitelist user
		if l_url[1] == url:
		   	return False
	return True


def spoof(target,defaultGateway):
	"""
	arp spoofs specific ip address
	utilizes arpspoof package
	"""
	Popen('arpspoof -i eth0 -t {} {}'.format(target,defaultGateway),shell=True) #-i [interface] -t [target] [gateway]

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
		sleep(20)

def setup():
	"""
	get all necessary values for the program to run
	and start all threads
	"""

	hosts=get_users_list()
	for host in hosts:
		new_host=get_user(host[1])
		if new_host[2] == 2:
			urls=get_urls(host[1])
			global user_list
			user_list.append(User(host[1],str(new_host[0]),new_host[1],urls))
			logging.debug('new user:{},{},{}'.format(host[1],host[0],user_list[-1].get_url_list()))
	print 'all users created'
	logging.info('all users created ({})'.format(len(user_list)))

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

	#add mac addresses to database that do not have a user associated with them
	add_new_hosts(localAddresses)

	#create process for spoofing all hosts on network
	arpThread=Process(target=arp_spoof,args=(defaultGateway,))
	logging.info('created process for ARP spoofing')
	arpThread.start()



def main(conn=None):
	"""
	control the whole program
	gets the parameters for working
	then calls all functions in order
	"""
	#setup logging to file logFile.log
	logging.basicConfig(filename='MITM_log.log',level=logging.DEBUG, format='%(lineno)s - %(levelname)s : %(message)s')
	logging.info('\n\n\n\n\n########## MITM Start ##########\n\n')

	global main_conn
	main_conn=conn
	#get all required variables and start all threads
	setup()
	logging.info('setup complete')
	global user_list
  sniff(prn=handle_packet)
	while True:
		command=main_conn.recv()

		if command==1:
			
			host_id=main_conn.recv()
			new_user=get_user(host_id)
			print "new user:"+str(new_user)
			
			user_list.append(User(host_id,str(new_user[0]),new_user[1],get_urls(host_id)))
			print "user add len:"+ str(len(user_list))
			
		elif command==2:
			host_id=main_conn.recv()
			for i in len(user_list):
				
				if host_id==user_list[i].get_id():
					del user_list[i]
					logging.info('user {} deleted'.format(host_id))
					

		elif command == 3:
			host_id=main_conn.recv()
			for i in range(len(user_list)+1):
				if host_id==user_list[i].get_id():
					user_list[i].update_url_list(get_urls(host_id))
					logging.debug('updated url list for user {}'.format(host_id))
			for host in user_list:
				print "urls:"+str(host.get_url_list())
					

		elif command==4:
			url_id=main_conn.recv()
			for host in user_list:
				if host.remove(url_id):
					logging.debug('url {} deleted for user {}'.format(url_id,host.get_id()))
					
		elif command==10:
			data=main_conn.recv()
			for host in user_list:
				if host.get_id() == data[0]:
					host.set_privilege(data[1])
					print "updated privilege "+data[0]
					





if __name__=='__main__':
    main()
