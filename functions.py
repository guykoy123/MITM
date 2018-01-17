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

    uses arp-scan package to scan network for all active hosts
    uses awk package to extract addresses
    """

    output =proc_output('arp-scan --localnet | awk \'{print $1}\'')
    return output.split('\n')[2:-4] #extract only IP addresses



def getLocalhostAddress():
    """
    returns default gateway address,
    Subnet Mask
    and localhost IP address

    uses ip route package to get default gateway address and local host IP address
    uses arping package to get local host MAC address
    """

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
            logging.debug('sent: '+packet.summary())
        except Exception as exc:
            logging.critical('error occured:'+packet.summary()+'/r/n'+str(exc))
            with open('error.txt','w') as f:
                f.write(packet.show())
    else:
        packet.show()




if __name__=='__main__':
    pass
