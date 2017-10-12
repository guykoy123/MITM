
try:
    import wmi,logging,scanip
    from scapy.all import * #missing pcapy
except ImportError:

    #TODO: handle all cases of missing modules and try to solve
    print 'a module is missing please check you have all required modules'
    print 'modules: wmi,logging,scanip,scapy'

def get_DG_LH():
    """
    returns default gateway address
    and local host IP address
    """
    wmi_obj = wmi.WMI() #create wmi object
    wmi_sql = "select IPAddress,DefaultIPGateway from Win32_NetworkAdapterConfiguration where IPEnabled=TRUE" #write sql command to rerieve IP addresses
    wmi_out = wmi_obj.query( wmi_sql )#send command and recieve addresses
    for i in wmi_out:
        return i.DefaultIPGateway[0],i.IPAddress[0]
    
def getLocalAddrss():
    """
    returns a dictionary of all LAN IP addresses and their coresponding MAC address
    """
    scanip.scanip.start_scan()

def arpSpoof(lanAddr):
    pass


def main():
    """
    control the whole program
    gets the parameters for working 
    then calls all functions in order
    """
    
    #setup logging to file logFile.txt
    logging.basicConfig(filename='logFile.txt',level=logging.DEBUG, format=' %(asctime)s - %(levelname)s - %(message)s')
    logging.info('\n\n\n\n\n\n\n########## Program Start ##########\n\n')
    
    #get default gateway and local IP address
    defaultGateway,localIP=get_DG_LH()
    logging.debug('got default gateway:%s and local IP: %s'%(defaultGateway,localIP))
    
    #create a dictionary of local IP addresses and MAC addresses


    while True: #main loop
        
        
        #send ARP broadcast
        #listen for packets
        #save packet
        #send packet to router
        #listen to response from router
        #save response
        #send packet to original host
        break

    #save packets to file


if __name__=='__main__':
    main()