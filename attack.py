import dns.resolver
import socket
from scapy.all import *
import random
import time
from ipaddress import IPv6Network, IPv6Address


def get_my_ip():
    ret = socket.gethostbyname(socket.gethostname())
    print (ret)
    return ret

def get_random_domain():
    '''
    Return a random domain name from top 10K sites listed on the file
    '''

    random.seed(time.time())
    filepath = 'opendns-top-domains.txt'
    domain_names = []
    with open(filepath) as fp:
        for cnt, line in enumerate(fp):
            domain_names.append(line)
    return random.choice(domain_names)

def random_ipv6_address():
    """
    Generate a random IPv6 address for a specified subnet
    """
    
    subnet = '2001:db8:100::/64'

    random.seed(time.time())
    network = IPv6Network(subnet)
    address = IPv6Address(network.network_address + getrandbits(network.max_prefixlen - network.prefixlen))

    print(address)
    return address

def step1():
    try:
        # getting a random domain name to query the dns server
        domain_name = get_random_domain()
        print(domain_name)
        result = dns.resolver.resolve(domain_name, 'A')
    
        # this is a dns.resolver.Answer object without the __dict__ command
        print(result.__dict__)
        print(result.response)

        #for printing the ip address of the query
        '''
        for ipval in result:
            print ('IP', ipval.to_text())
        '''

    except dns.exception.Timeout:
        print ("Timeout on DNS query.")
    except dns.resolver.NXDOMAIN:
        print ("The query name does not exist.")

def step2():
    #need to run this file with sudo because of port 53
    
    forwarder_port = 53
    forwarder_ip = '127.0.0.1'

    '''
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.connect((forwarder_ip, forwarder_port)) #You can't do the next command without this
    sender.send(bytes('IP packet', encoding='utf8'))
    '''
    attacker_port = 1200
    attacker_ip = '127.0.0.150'

    # initially trying to send a upd probe packet to the dns server to get any reply first
    # using the actual ip of this machine, but not getting it at this moment
    ip_layer = IP(dst=forwarder_ip) # not specifying the src, so that scapy can fill this up
    udp_layer = UDP(dport=forwarder_port, sport=attacker_port)
    dns_layer = DNS(rd=1,qd=DNSQR(qname=get_random_domain()))
    packet = ip_layer / udp_layer / dns_layer
    #send(packet)
    ret = sr(packet)
    print(ret)

    '''
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind((attacker_ip, attacker_port))
    while True:
        data, addr = receiver.recvfrom(65565) # depends on the size of udp packet
    '''


    #ret = dns.resolver.answer()

def main():
    #step1();
    step2();

if __name__ == "__main__":
    main()