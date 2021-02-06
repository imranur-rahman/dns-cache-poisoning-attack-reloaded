from scapy.all import *

sock = conf.L2socket(iface='vboxnet2')


ip_layer = IP(dst='192.168.58.2') # leaving src to be filled up by scapy
udp_layer = UDP(dport=2560, sport=RandShort())
verification_packet = Ether() / ip_layer / udp_layer

'''
# working
reply = sock.sr1(verification_packet, timeout=1, verbose=False) # in seconds

if reply == None:
    print ("No reply found.")
else:
    print (reply.show())
'''
raw_packet = raw(verification_packet)
for i in range(20):
    sock.send(raw_packet)
