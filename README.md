# DNS cache poisoning attack reloaded (ACM CCS '2020).

## Introduction

For the demonstration purpose of the attack I have used three VM's to implement the DNS system:

- DNS forwarder (using dnsmasq on FreeBSD 12.2)
- DNS resolver (using dnsmasq on Ubuntu Server 20.04.1, Linux 5.4.0)
- Authoritative name server (using bind9 on Ubuntu Server 20.04.1, Linux 5.4.0)


The script will issue a DNS query and wait for the response on a thread, and on a separate thread it will first try to infer the source port (used by the forwarder to send the query to the upstream resolver) and when it will find an open source port, it will issue spoofed
dns responses (with varying TxID) to the forwarder to poison it's cache.

## Demonstration

Youtube video link: https://youtu.be/Jo0pH_Iz_Qc (Please check the change in ip address for "cool.com" in two different runs)

## References

1. Keyu Man, Zhiyun Qian, Zhongjie Wang, Xiaofeng Zheng, Youjun Huang, and Haixin Duan. 2020. DNS Cache Poisoning Attack Reloaded: Revolutions with Side Channels. In Proceedings of the 2020 ACM SIGSAC Conference on Computer and Communications Security (CCS '20). Association for Computing Machinery, New York, NY, USA, 1337–1350. DOI:https://doi.org/10.1145/3372297.3417280