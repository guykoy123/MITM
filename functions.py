#python 2.7

import wmi
from scapy.all import *

# global variables:
localHost=[]

def getLocalhostAddress():
    """
    returns default gateway address,
    Subnet Mask
    and localhost IP address"""
    l=[]
    c = wmi.WMI() #create wmi object
    for interface in c.Win32_NetworkAdapterConfiguration (IPEnabled=1):
        global localhost
        localHost.append(interface.IPAddress[0].encode('ascii').lower())
        localHost.append(interface.MACAddress.encode('ascii').lower())
        return interface.DefaultIPGateway[0],interface.IPSubnet[0],localHost


def sendPacket(packet,defaultGateway):
    """
    sends packet to intended destination
    """
<<<<<<< HEAD
    #TODO: test function
=======
>>>>>>> 336b261ab36e2e99779e15bb366f6a25bc51e4a6
    if IP in packet:
        packet[IP].pdst=defaultGateway[0]
        packet[Ether].hwdst=defaultGateway[1] # set destination address to routers address
        sendp(packet) # send the packet

    elif ARP in packet:
        if packet[ARP].pdst==defaultGateway[0]:
            srcIP=packet[ARP].psrc
            srcMAC=packet[ARP].hwsrc # save source address

            packet[ARP].psrc=defaultGateway[0]
            packet[ARP].hwsrc=localHost[1] # set source address to router IP and localhost MAC

            packet[ARP].op=2 # set operation code to 2 (is-at)

            packet[ARP].pdst=srcIP # set destination address to source address
            packet[ARP].hwdst=srcMAC

            sendp(packet) # send packet
    else:
        print packet.show()




if __name__=='__main__':
    pass
