#python 2.7


#from scapy.all import *
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

    output =proc_output('arp-scan --localnet | awk \'{print $1,$2}\'')
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
    #logging.info('got default gateway'+defaultGateway)

    localHost=proc_output('ip route | awk \'/src/ { print $9 }\'')
    #logging.info('got localhost ip'+localHost)

    return defaultGateway,localHost



if __name__=='__main__':
    pass
