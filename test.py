from scapy.all import *
import random
import time
from ipaddress import IPv6Network, IPv6Address

sock = conf.L2socket(iface='vboxnet2')

forwarder_ip = '192.168.58.2'
forawrder_ipv6 = '2100::101'

my_ip = '192.168.58.1'
my_ipv6 = '2100::100'


def initialize():
    # Initialize local_free_ip list
    local_ip_base = '192.168.58.'
    start = 5
    end = 254
    now = start
    local_free_ip = []
    while now <= end:
        local_free_ip.append(local_ip_base + str(now))
        now += 1
    #print (local_free_ip)
    print (len(local_free_ip))
    return local_free_ip

local_free_ip = initialize()

verification_packet = Ether() / IP(dst=forwarder_ip, src=my_ip) / UDP(dport=1)

packets = [raw(Ether() / IP(dst=forwarder_ip, src=my_ip) / UDP(dport=1, sport=RandShort())) for i in range(200)]

start_time = time.perf_counter()
for packet in packets:
    sock.send(packet)
elapsed_time = time.perf_counter() - start_time
print (elapsed_time)
reply = sock.sr1(verification_packet, timeout=.1)
elapsed_time = time.perf_counter() - start_time
print (elapsed_time)


'''
# working
reply = sock.sr1(verification_packet, timeout=1, verbose=False) # in seconds

if reply == None:
    print ("No reply found.")
else:
    print (reply.show())
'''
'''
# getting only 6 ICMP replies for 20 packets
raw_packet = raw(verification_packet)
for i in range(20):
    sock.send(raw_packet)
'''
'''
# working
packet6 = IPv6(dst=forawrder_ipv6) / ICMPv6EchoRequest(data='ssdf')
reply = sr1(packet6)
print (reply.show())
'''

'''
# getting only 6 ICMP replies for 20 packets
packet6 = Ether() / IPv6(dst=forawrder_ipv6) / UDP(dport=1)
r = raw(packet6)
for i in range(20):
    sock.send(r)
'''

'''
packets = [raw(Ether() / IPv6(dst=forawrder_ipv6, src=RandIP6()) / UDP(dport=1)) 
            for i in range(50)]
ver_packet = Ether() / IPv6(dst=forawrder_ipv6, src=my_ipv6) / UDP(dport=1, sport=RandShort())

start_time = time.perf_counter()
for packet in packets:
    sock.send(packet)
elapsed_time = time.perf_counter() - start_time
print (elapsed_time)
reply = sock.sr1(ver_packet, timeout=.1)
elapsed_time = time.perf_counter() - start_time
print (elapsed_time)
'''