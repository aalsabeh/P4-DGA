#!/usr/bin/python

import os
import sys
import scapy
from scapy.all import *
import dpkt
import struct
import time
import crcmod

if os.getuid() !=0:
    print("ERROR: This script requires root privileges. Use 'sudo' to run it.")
    quit()

try:
    ip_dst = sys.argv[1]
except:
    ip_dst = "192.168.1.2"

try:
    iface = sys.argv[2]
except:
    iface="veth0"
    
def pcap_parser(pcap_file_name):
    counter=0
    ipcounter=0
    tcpcounter=0
    udpcounter=0
    dnscounter=0
    dns_packets = []

    for ts, pkt in dpkt.pcap.Reader(open(pcap_file_name, 'rb')):
    
        counter += 1
        try:
            eth = dpkt.ethernet.Ethernet(pkt)
            ip = eth.data
            udp = ip.data
            if udp.sport != 53 and udp.dport != 53:
                continue
            dns = dpkt.dns.DNS(udp.data)
            if len(dns.an) < 1:
                continue
            for qname in dns.qd:
                domain = qname.name
                break
            if domain == "officecdn.microsoft.com":
                continue
            print(counter)
            sendp(pkt, iface=iface)
            break
        except e as Exception:
            print(counter, e)

        ''' 
        eth=dpkt.ethernet.Ethernet(pkt) 
        if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
            continue

        ip = eth.data

        if ip.p==dpkt.ip.IP_PROTO_UDP:
            udp = ip.data
            udpcounter+=1
            if udp.dport == 53 or udp.sport == 53:
                dnscounter += 1
                try:
                    dns = dpkt.dns.DNS(udp.data)
                    if dns.rcode == dpkt.dns.DNS_RCODE_NOERR or dns.qr == dpkt.dns.DNS_R or dns.opcode == dpkt.dns.DNS_QUERY:
                        # DNS question.
                        
                            if dns.id == 0xf153 and counter > 3:
                                print("hi", counter)
                                dns_packets.append(pkt)
                                # print (dns.qd[0].name)
                                # print (dns.qd[0].type)
                                print (dns.ar[0].type)
                                break
                                # q_name = dns.qd[0].name
                                # q_type = dns.qd[0].type

                        #     for answer in dns.an:
                        #         # print (answer)
                        #         if answer.type == dpkt.dns.DNS_A:
                        #             try:
                        #                 print (socket.inet_ntoa(answer.rdata))
                        #             except socket.error:
                        #                 print("Error answer data")
                except Exception as e:
                    print (e)
                    # return False

                    
                # print (dns)

        # if dnscounter == 1000:
        #     break
        '''
    return dns_packets

#dns_packets = pcap_parser("dns-traffic.20140613.pcap")
# dns_packets = pcap_parser("20160423_235403.pcap")
# dns_packets = pcap_parser("dns_a_records.pcap")



src_ip = "10.11.12.13"

print("Sending IP packet to", ip_dst)
p = (Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee")/
     IP(src=src_ip, dst=ip_dst)/
     UDP(dport=80, sport=80)/
     "This is a test12345678")


dns_p = (Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee")/
        IP(src=src_ip, dst=ip_dst)/
        UDP(dport=53, sport=53)/
        DNS(id=1, ancount=8, qdcount=1, qr=1,
        qd=DNSQR(qname='officecdn.microsoft.com', qtype=1),
        an=DNSRR(rrname="aa", type = 5, rdata="0"*42)/
           DNSRR(rrname="aa", type = 5, rdata="0"*24)/
           DNSRR(rrname="aa", type = 5, rdata="0"*29)/
           DNSRR(rrname="aa", type = 5, rdata="0"*41)/
           DNSRR(rrname="aa", type = 5, rdata="0"*57)/
           DNSRR(rrname="aa", type = 5, rdata="0"*22)/
           DNSRR(rrname="aa", rdata="1.1.1.1")/
           DNSRR(rrname="aa", rdata="1.1.1.1"))
        )


qname = 'officecdnaaaaaaa.microsoft.com'
qname = "officecdn.microsoft.com.comcom.jojo"
qname = "officecdnaaaaaa.abcdabcdabcdabca.abcdabcdabcdabcd"
qname = "jojo.lolo.bobo.hoho.abcdabcdabcdabca"
qname = "jojo.lolo.bobo.hoho.koko.fofo.mimi.riri.lili"
#qname = "officecdnaaaaaaa.abcd-efgh-ijkl-mn.oo.kk.lolololololololo"

#qname = "aa.bb.cc.dd.ee"
qname = "creaderss.com"
qname = "creaders.net"
qname = "xz.xz"
qname = "a.ffcebo.cuisinella"
qname = "efefeeabc.goocreaderssgle.directory"
qname = "google.com"
qname = "facebook.com"
#qname = "xcyz.xcyz"
#qname = "eqqzlxz3f37568225a5f.cz"

# dns_query = (Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee")/
#         IP(src=src_ip, dst=ip_dst)/
#         UDP(dport=53, sport=53)/
#         DNS(id=1, ancount=1, qdcount=1, qr=1,
#         qd=DNSQR(qname=qname, qtype=1),
#         an= DNSRR(rrname=qname, rdata="1.1.1.1")) 
#         )

dns_query = (Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee")/
        IP(src=src_ip, dst=ip_dst)/
        UDP(dport=53, sport=53)/
        DNS(id=1, qr=1, opcode=0, aa=1, tc=0, rd=1, ra=1, z=0, ad=0, cd=0, rcode=3,
            qdcount=1, ancount=0, nscount=0,arcount=0,
            qd=DNSQR(qname=qname, qtype=1),
            an= DNSRR(rrname=qname, rdata="1.1.1.1"))
        )

dns_query = scapy.layers.dns.DNS.compress(dns_query)

for i in range(1):
    print(dns_query)
    sendp(dns_query, iface=iface)
#sendp(p, iface=iface)
