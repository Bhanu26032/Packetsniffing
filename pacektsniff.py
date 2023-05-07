#run it as administrator then only it runs
import socket
import struct

# create a raw socket and bind it to all interfaces
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind(('ip_address yours one', "port of your computer you need to run we can specify it as 0 if you wish without quotes"))

# set the socket to promiscuous mode
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# receive packets in a loop
while True:
    packet = s.recvfrom(65535)
    ip_header = packet[0][0:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    ttl = iph[5]
    protocol_num = iph[6]
    protocol = ""
    if protocol_num == 6:
        protocol = "TCP"
    elif protocol_num == 17:
        protocol = "UDP"
    else:
        protocol = "Other"
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    print(f"Protocol: {protocol}, Source Address: {s_addr}, Destination Address: {d_addr}")

    if protocol == "TCP":
        tcp_header = packet[0][iph_length:iph_length+20]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
        source_port = tcph[0]
        dest_port = tcph[1]
        print(f"TCP Source Port: {source_port}, TCP Destination Port: {dest_port}")

    if protocol == "UDP":
        udp_header = packet[0][iph_length:iph_length+8]
        udph = struct.unpack('!HHHH', udp_header)
        source_port = udph[0]
        dest_port = udph[1]
        print(f"UDP Source Port: {source_port}, UDP Destination Port: {dest_port}")

    if protocol == "TCP" and (source_port == 23 or dest_port == 23):
        telnet_data = packet[0][iph_length+20:]
        print(f"Telnet Data: {telnet_data}")

    if protocol == "TCP" and (source_port == 80 or dest_port == 80):
        http_data = packet[0][iph_length+20:]
        print(f"HTTP Data: {http_data}")

# turn off promiscuous mode and close the socket
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
s.close()
