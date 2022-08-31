#Amirreza Hosseini

from email import message
from socket import *
import os
from binascii import unhexlify
from pytz import utc

#message = "ac7ba14f4c0fea18"

s = socket(AF_PACKET, SOCK_RAW)

message = input("What is your packet content?\n" )

interface = input("Which interface do you want to use?\n" )


#pkt = " ".join(message[i:i+2] for i in range(0, len(message), 2))


#change hex to ascii
# hex="23 45 67 89 11 23"
# hex = hex.split()
# hex = [int(x, 16) for x in hex]
# hex = [chr(x) for x in hex]
# hex = "".join(hex)
# pkt=unhexlify(hex)
#pkt=pkt[:0] + unhexlify(hex) + pkt[6:]

#change hex to ascii
# hex="12 34 56 78 90 12"
# hex = hex.split()
# hex = [int(x, 16) for x in hex]
# hex = [chr(x) for x in hex]
# hex = "".join(hex)
#pkt = pkt[:6] + hex + pkt[12:]

# pkt += unhexlify((hex))

#pkt=pkt[:6] + unhexlify(hex) + pkt[12:]

#message='#Egp3#'+"4Vxas"

string="980230000021123456789012bcac"


pkt=unhexlify((message))


s.bind((interface, 0))
s.send(pkt)

#find the packet length in byte
pkt_len = len(pkt)

print("send %d-bytes packet on %s" % (pkt_len, interface))
