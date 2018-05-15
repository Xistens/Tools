#!/usr/bin/python2.7
import socket
import struct
from ctypes import Structure, c_ubyte, c_ushort, c_uint32

class IP(Structure):
    """ Map the first 20 bytes into a friendly IP header """
    _fields_ = [
        ("ihl",             c_ubyte, 4),
        ("version",         c_ubyte, 4),
        ("tos",             c_ubyte),
        ("len",             c_ushort),
        ("id",              c_ushort),
        ("offset",          c_ushort),
        ("ttl",             c_ubyte),
        ("protocol_num",    c_ubyte),
        ("sum",             c_ushort),
        # Changed src and dst to c_uint32 from c_ulong
        ("src",             c_uint32),
        ("dst",             c_uint32)
    ]
    
    def __new__(self, socket_buffer=None):
        """ Takes in a raw buffer and forms the structure from it """
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        """ Setup human readable output for the protocol in use and the IP addresses """
        # map protocol constants to their names
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

        # human readable IP addresses
        # Convert an IP address from 32-bit packed binary format to string format
        #'@I' is unisigned int in native order. because c_ulong is 4 bytes in i386 and 8 in amd64. 
        self.src_address = socket.inet_ntoa(struct.pack("@I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I", self.dst))

        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except KeyError:
            self.protocol = str(self.protocol_num)