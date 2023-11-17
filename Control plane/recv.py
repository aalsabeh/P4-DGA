#!/usr/bin/python

import os
import sys
from scapy.all import *


try:
    iface=sys.argv[1]
except:
    iface="veth1"

if os.getuid() !=0:
    print ("ERROR: This script requires root privileges. Use 'sudo' to run it.")
    quit()



received_packets = 0
ingress_timestamps_ls = []
egress_timestamps_ls = []
timestamps_difference_ls = []

def timestamp_python2(p):
    '''
    - Takes a scapy packet,
    
    - Returns the ingress time, egress time, and the difference extracted
    from the first 16 bytes of the packet
    '''
    ingress_timestamp = ""
    egress_timestamp = ""
    byte_num = 1
    
    for b in str(p):
        hex_ord_b = hex(ord(b))
        if byte_num <= 6:
            # 0xa, which is 0x0a
            if len(hex_ord_b) < 4 :
                ingress_timestamp += "0" + hex_ord_b[2:]
            elif len(hex_ord_b) == 4:
                ingress_timestamp += hex_ord_b[2:]
        elif byte_num > 6 and byte_num <= 12:
            # 0xa, which is 0x0a
            if len(hex_ord_b) < 4 :
                egress_timestamp += "0" + hex_ord_b[2:]
            elif len(hex_ord_b) == 4:
                egress_timestamp += hex_ord_b[2:]
        else:
            break
        byte_num += 1
    ingress_timestamp = int(ingress_timestamp, 16)
    egress_timestamp = int(egress_timestamp, 16)
    ingress_timestamps_ls.append(ingress_timestamp)
    egress_timestamps_ls.append(egress_timestamp)
    print(egress_timestamp - ingress_timestamp)
    timestamps_difference_ls.append(egress_timestamp - ingress_timestamp) 
    if len(egress_timestamps_ls) == 5:
        print(timestamps_difference_ls)

def timestamp_python3(p):
    ingress_timestamp = ingress_timestamps_ls.append(int(bytes(p)[0:6].hex(), 16))
    egress_timestamp = ingress_timestamps_ls.append(int(bytes(p)[6:12].hex(), 16))
    timestamps_difference.append(egress_timestamp - ingress_timestamp)
    
    if len(ingress_timestamp) == 1000:
        print(sum(timestamps_difference)/len(timestamps_difference))
    

print("Sniffing on ", iface)
print("Press Ctrl-C to stop...")
# sniff(iface=iface, prn=timestamp_python2)
sniff(iface=iface, prn=lambda p: p.show())

'''
if sys.version_info >= (3, 7):
    print("python 3")
    sniff(iface=iface, prn=timestamp_python3)
else:
    sniff(iface=iface, prn=timestamp_python2)
'''

