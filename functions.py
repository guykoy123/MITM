#python 2.7


from scapy.all import *
import subprocess



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
    temp=output.split('\t')[:-1]
    addrs=[]
    for i in temp:
        addrs.append( i.split('\n')[-1])

    localAddresses=list()
    for i in range(0,len(addrs),2):
        host=addrs[i]
        if host != defaultGateway or host != localHost: #check if the ip is not the local host's ip or the default gateway
            localAddresses.append(host)
    """

    output =proc_output('arp-scan --localnet | awk \'{print $1}\'')
    localAddresses=output[2:-3]
    print localAddresses
    return localAddresses

def getLocalhostAddress():
    """
    returns default gateway address,
    Subnet Mask
    and localhost IP address"""

    defaultGateway=proc_output('ip route | awk \'/default/ { print $3 }\'')
    logging.debug('got default gateway')
    localHost=proc_output('ip route | awk \'/src/ { print $9 }\'')
    logging.debug('got localhost ip')
    gatewayMAC=proc_output("arping -f -I $(ip route show match 0/0 | awk '{print $5, $3}')|awk '{print  $5}' | grep '\['")[1:-2]
    logging.debug('got default gateway MAC')


    return defaultGateway,localHost,gatewayMAC

def sendPacket(packet,gatewayMAC):
    """
    sends packet to intended destination
    """
    #TODO: rewrite
    if Ether in packet:

        packet[Ether].dst=gatewayMAC
        try:
            sendp(packet)
            #packet.show()
            logging.debug('sent: '+packet.summary())
        except Exception as exc:
            logging.critical('error occured:'+packet.summary()+'/r/n'+str(exc))
            with open('error.txt','w') as f:
                f.write(packet.show())
    else:
        packet.show()




if __name__=='__main__':
    pass
