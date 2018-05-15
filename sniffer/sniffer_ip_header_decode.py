#!/usr/bin/python2.7
import socket
import os
from ip import IP

# host to listen on
HOST = "0.0.0.0"

def main():
    """ main block """
    if os.name == "nt":
        # Windows
        socket_protocol = socket.IPPROTO_IP
    else:
        # Internet Control Message Protocol
        socket_protocol = socket.IPPROTO_ICMP

    # Raw socket means you can determine every section of packet, either header or payload
    # Layer3 socket, Network Layer Protocol = IPv4
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))

    # we want the IP headers included in the capture
    # HDRINCL, when true, indicates the app provides the IP header. Only to SOCKET_RAW
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # if we're on Windows we need to send som ioctls
    # to setup promiscuous mode
    if os.name == "nt":
        # SIO_RCVALL control code enables a socket to receive all IPv4 or IPv6 packets
        # passing through a network interface
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    
    try:
        while True:
            # read in a single packet
            raw_buffer = sniffer.recvfrom(65565)[0]

            # create an IP header from the first 20 bytes of the buffer
            ip_header = IP(raw_buffer[0:20])

            print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
    except KeyboardInterrupt:
        # if we're on Windows turn off promiscuous mode
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == "__main__":
    main()