def IMCP_reply_limit_check():
    print("ICMP reply limit checking function")

    #print("Sleeping for 50ms")
    time.sleep(0.05)

    start_time = time.process_time()

    #now_port = port_start

    # generate all probe packets, padding_packets (if any) and the verification packet first
    # and then send those in a burst


    ip_layer = IP(dst=forwarder_ip, src=RandIP())
    udp_layer = UDP(dport=1, sport=RandShort())
    packet = ip_layer / udp_layer
    #padding_packet.append(packet)

    ip_layer = IP(dst=forwarder_ip) # leaving src to be filled up by scapy
    udp_layer = UDP(dport=1, sport=RandShort())
    verification_packet = ip_layer / udp_layer

    elapsed_time = time.process_time() - start_time
    print ("Time needed for generating packets: " + str(elapsed_time))

    # improving scapy's packet sending performance
    # https://byt3bl33d3r.github.io/mad-max-scapy-improving-scapys-packet-sending-performance.html


    start_time = time.process_time()
    for i in range(ICMP_limit_rate):
        global_socket.send(packet)
    elapsed_time = time.process_time() - start_time
    print ("Time needed for sending 50 packets: " + str(elapsed_time))

    #print("Sending verification packet")

    start_time = time.process_time()

    # This timeout is the crucial factor
    reply = sr1(verification_packet, timeout=3, verbose=True) # in seconds

    elapsed_time = time.process_time() - start_time
    print ("Time needed for sending and receiving verification packet: " + str(elapsed_time))
    #print("Got reply from verificaiton packet")
    #print (reply.show())

    #multiple packet send using sr
    #answered, unanswered = sr(IP(dst=”192.168.8.1”)/TCP(dport=[21,22,23]))
    #Received 6 packets, got 3 answers, remaining 0 packet


    # if timeout occurs even then the reply will be none
    if reply == None:
        print ("Didn't get anything. No open port in this chunk.")
        return -1 # important for the base condition of the binary search
    else:
        if reply.haslayer(ICMP):
            # Maybe need to check the error code also
            print("Yaaaay., got ICMP port unreachable message. At least one port is open.")
            #print (reply[ICMP].summary())
            #print (reply[ICMP].show())
            return 1
        elif reply.haslayer(UDP):
            print("Don't know what this means.")
        else:
            print("Unknown reply")

    return 0 # for now
