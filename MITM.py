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
localAddresses=[]
addressesLock=Lock()
gatewayMAC=''
bad_packet=[]
user_list=[]
localHost=''
main_conn=Pipe()

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
        #print pkt.show()
        #TODO: implement computer block list


        if TCP in pkt:
            if 80 == pkt[TCP].dport: #check if packet is http packet
                #pkt.show()
                logging.info("HTTP:"+ pkt.summary())

                try:
                    fields=str(pkt[Raw]).split('\r\n') #split into packet fields
                    #logging.info(str(fields))
                    for field in fields:
                        if 'Host:' == field[:5]:        #if Host field exctract url
                            url=field[5:]
                            break

                    if (url != None):
                        logging.info("URL:"+url)
                        ip=pkt[IP]

                        if url == "networkmanager.com" or url == "www.networkmanager.com":
                            functions.redirect_to_login(ip)
                        else:
                            new_user=True
                            for user in user_list:
                                if ip == user.get_ip():
                                    new_user=False
                                    if not blocked(user,url):
                                        functions.sendPacket(pkt,gatewayMAC)
                                    else:
                                        pass
                                        #TODO: return page is blocked
                            if new_user:
                                functions.redirect_to_login(ip)





                    else:
                        logging.warning('url field not found') #save packets that cause errors
                        wrpcap('error.pcap',pkt)
                except Exception as exc:
                    print exc
                    #logging.warning('failed to extract url, '+str(exc),'in:',pkt.summary())
    else:
        if pkt[ARP].op == 2: #check if ARP operation is: is-at
            address=pkt[ARP].psrc #extract IP address
            addressesLock.acquire()
            global localAddresses
            if address not in localAddresses: #check for duplicates
                localAddresses.append(address) #add IP address to list of all hosts
                print 'added',address
            addressesLock.release()



def arpSpoof(router,localHost):
    """
    every 30 seconds send ARP broadcast to spoof all machines on LAN
    """
    while True:
        if len(localAddresses)>0:
            addressesLock.acquire()
            print 'spoofing',str(len(localAddresses))
            for host in localAddresses:
                if host != router and host != localHost: #check that ip does not match default gateway or local host to not send packets to them

                    victimPacket = Ether()/ARP(op=2,psrc = router, pdst=host)#create arp packets
                    gatewayPacket=Ether()/ARP(op=2,psrc=host,pdst=router)
                    logging.debug('spoofing: '+victimPacket[ARP].pdst)
                    sendp(victimPacket,verbose=0)#send packets
                    sendp(gatewayPacket,verbose=0)

            addressesLock.release()
            print 'done spoofing'
            sleep(30)




def setup():
    """
    get all necessary values for the program to run
    and start all threads
    """
    #get default gateway, local IP address and local MAC address
    global gatewayMAC
    global localHost
    defaultGateway,localHost,gatewayMAC=functions.getLocalhostAddress()
    print defaultGateway,gatewayMAC,localHost
    logging.debug('got default gateway and local IP and MAC')

    global localAddresses
    localAddresses=functions.get_Local_Addresses(defaultGateway,localHost) #get addresses of all hosts on network
    logging.debug('scanned network for all active hosts')
    print localAddresses

    arpThread=Thread(target=arpSpoof,args=(defaultGateway,localHost,))
    logging.debug('created thread for ARP spoofing')
    arpThread.start()
    logging.debug('spoofing all hosts on network')




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

    sniff(prn=handle_Packet)


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
