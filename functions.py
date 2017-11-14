#python 2.7


from scapy.all import *

# global variables:
localHost=[]

def getLocalhostAddress():
    """
    returns default gateway address,
    Subnet Mask
    and localhost IP address"""
    pass
    #TODO: convert to linux with ifconfig|grep

def sendPacket(packet,defaultGateway):
    """
    sends packet to intended destination
    """
    #TODO: test function
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
