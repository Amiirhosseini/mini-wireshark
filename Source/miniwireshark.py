from struct import *
import re
import socket
import struct
import sys
import textwrap
import binascii


 
    
    
def ethernet_head(raw_data):
    proto = ""
    IpHeader = struct.unpack("!6s6sH",raw_data[0:14])
    dstMac = binascii.hexlify(IpHeader[0]) 
    srcMac = binascii.hexlify(IpHeader[1]) 
    protoType = IpHeader[2] 
    nextProto = hex(protoType) 
    raw_data = raw_data[14:]
    return dstMac, srcMac, proto, raw_data





def ipv4_head(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    data = raw_data[header_length:]
    src = get_ip(src)
    target = get_ip(target)
    return version, header_length, ttl, proto, src, target, data


def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = s.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_head(raw_data)
        ipv4 = ipv4_head(data)
        if ipv4[3] == 6:
            tcp = tcp_head(ipv4[6])
            print('port {}'.format(tcp[1])+ ' is open on',ipv4[4] )
            print('--------------------------')




def get_ip(addr):
    return '.'.join(map(str, addr))


def tcp_head(raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack(
	    '! H H L L H', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    data = raw_data[offset:]
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack,flag_psh, flag_rst, flag_syn, flag_fin, data




main()

