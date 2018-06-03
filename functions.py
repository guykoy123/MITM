#python 2.7


from scapy.all import *
import subprocess


def redirect_to_login(pkt):
    print "redirected to login page"
    redirectStr='HTTP/1.0 302 FOUND\r\nLocation: http://192.168.1.10/user_login\r\n\r\n'
    new_pkt=Ether()/IP(dst=pkt[IP].src)/TCP(sport=80,ack=pkt[TCP].ack,seq=pkt[TCP].seq,dport=pkt[TCP].sport)/(redirectStr)
    send(new_pkt)

def proc_output(command):
    """
    returns output of command in the linux shell
    """

    proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    (output, err) = proc.communicate()
    return output


def get_Local_Addresses(defaultGateway,localHost):
    """
    scan network for all active hosts
    and return list of all IP addresses

    uses arp-scan package to scan network for all active hosts
    uses awk package to extract addresses
    """

    output =proc_output('arp-scan --localnet | awk \'{print $1,$2}\'') #TODO: add MAC address extraction
    ip_n_mac=output.split('\n')[2:-4] #extract only IP and MAC addresses (in one line)
    addresses={}
    for i in ip_n_mac:
    	addrss=i.split(' ')
    	addresses[addrss[0]]=addrss[1]
    return addresses



def getLocalhostAddress():
    """
    returns default gateway address,
    Subnet Mask
    and localhost IP address

    uses ip route package to get default gateway address and local host IP address
    uses arping package to get local host MAC address
    """

    defaultGateway=proc_output('ip route | awk \'/default/ { print $3 }\'')[:-1]
    logging.info('got default gateway'+defaultGateway)

    localHost=proc_output('ip route | awk \'/src/ { print $9 }\'')
    logging.info('got localhost ip'+localHost)

    gatewayMAC=proc_output("arping -f -I $(ip route show match 0/0 | awk '{print $5, $3}')|awk '{print  $5}' | grep '\['")[1:-2]
    logging.info('got default gateway MAC'+gatewayMAC)

    return defaultGateway,localHost,gatewayMAC



def sendPacket(packet,gatewayMAC):
    """
    sends packet to intended destination
    """
    #TODO: rewrite
    if Ether in packet:

        packet[Ether].dst=gatewayMAC
        #packet[Ether].src='08:00:27:78:5b:be'
        try:
            sendp(packet,verbose=0)
            logging.info('sent: '+packet.summary())
        except Exception as exc:
            logging.critical('error occured:'+packet.summary()+'/r/n'+str(exc))

    else:
        #packet.show()
        pass




if __name__=='__main__':
    pass
