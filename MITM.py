#python 2.7


import logging
from threading import Thread,Lock
from time import sleep
from scapy.all import *
from datetime import datetime
import functions
from network_monitor import network_monitor
import Queue
from multiprocessing import Process,PIPE
# except ImportError:
#
#     #TODO: handle all cases of missing modules and try to solve
#     print 'a module is missing please check you have all required modules'

# global variables:
localHost=''
defaultGateway=''
localAddresses=[]
addressesLock=Lock()


def handle_Packet(pkt):
    """
    add sniffed packets to queue of prescanned packets
    send it forward
    """
    if ARP not in pkt:
        pass
        #TODO: decide if to do live scanning or adding to queue and then scanning
    pass
    #functions.sendPacket(pkt,localAddresses)






def get_Local_Addresses(defaultGateway,localHost):
    """
    scan network for all active hosts
    """

    output =functions.proc_output('arp-scan --localnet')
    temp=output.split('\t')[:-1]
    addrs=[]
    for i in temp:
        addrs.append( i.split('\n')[-1])

    global localAddresses
    for i in range(0,len(addrs),2):
        host=addrs[i]
        if host != defaultGateway or host != localHost: #check if the ip is not the local host's ip or the default gateway
            localAddresses.append(host)
    print localAddresses


def setup():
    """
    get all necessary values for the program to run
    and start all threads
    """
    #get default gateway and local IP address
    global defaultGateway
    global localHost
    defaultGateway,localHost=functions.getLocalhostAddress()
    print defaultGateway,localHost
    logging.debug('got default gateway and local IP')

    get_Local_Addresses(defaultGateway,localHost) #get addresses of all hosts on network
    logging.debug('scanned network for all active hosts')

    #TODO: create process that will run network_monitor
    #TODO: create PIPE to communicate with network_monitor



def main():
    """
    control the whole program
    gets the parameters for working
    then calls all functions in order
    """
    #setup logging to file logFile.txt
    logging.basicConfig(filename='logFile.txt',level=logging.DEBUG, format='%(lineno)s - %(levelname)s : %(message)s')
    logging.info('\n\n\n\n\n########## Program Start ##########\n\n')

    setup() #get all required variables and start all threads
    logging.info('setup complete')


    sniff(prn=handle_Packet)

    while True:
        pass
    #TODO: add function to scan packets and update information about each device



if __name__=='__main__':
    main()
