#python 2.7


from scapy.all import *
import subprocess

# global variables:
localHost=[]



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
    """

    output =proc_output('arp-scan --localnet')
    temp=output.split('\t')[:-1]
    addrs=[]
    for i in temp:
        addrs.append( i.split('\n')[-1])

    localAddresses=list()
    for i in range(0,len(addrs),2):
        host=addrs[i]
        if host != defaultGateway or host != localHost: #check if the ip is not the local host's ip or the default gateway
            localAddresses.append(host)
    return localAddresses

def getLocalhostAddress():
    """
    returns default gateway address,
    Subnet Mask
    and localhost IP address"""

    defaultGateway=proc_output('ip route | awk \'/default/ { print $3 }\'')
    localHost=proc_output('ip route | awk \'/src/ { print $9 }\'')
    return defaultGateway,localHost

def sendPacket(packet,defaultGateway):
    """
    sends packet to intended destination
    """
    #TODO: rewrite
    pass




if __name__=='__main__':
    pass
