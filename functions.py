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
