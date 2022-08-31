
from binascii import unhexlify
from socket import inet_aton

def header_checksum(header, size):
    cksum = 0
    pointer = 0

    # The main loop adds up each set of 2 bytes. They are first converted to strings and then concatenated
    # together, converted to integers, and then added to the sum.
    while size > 1:
        cksum += int((str("%02x" % (header[pointer],)) +
                      str("%02x" % (header[pointer + 1],))), 16)
        size -= 2
        pointer += 2
    if size:  # This accounts for a situation where the header is odd
        cksum += header[pointer]

    cksum = (cksum >> 16) + (cksum & 0xffff)
    cksum += (cksum >> 16)

    return (~cksum) & 0xFFFF

def cs(data):
    data = data.split()
    data = [int(item,16) for item in data]
    return  "%04x" % (header_checksum(data, len(data)),)



# checksum functions needed for calculation checksum
# def cs(msg):
#     s = 0
#     # loop taking 2 characters at a time
#     for i in range(0, len(msg), 2):
#         w = (msg[i] << 8) + (msg[i + 1])
#         s = s + w

#     s = (s >> 16) + (s & 0xffff)
#     # s = s + (s >> 16);
#     # complement and mask to 4 byte short
#     s = ~s & 0xffff

#     return s




fd= open("info.txt", 'r') 
Lines = fd.readlines()

dest_mac = Lines[6][:17] #destination mac 
src_mac = Lines[5][:17] #source mac 
proto3 = "08 00" #layer 3 protocol number 
ver="45" #version, header length
diff = "00" #diffserv
t_len = "00 28" #total length ("00 28" for 40 bytes, "00 3c" for 60 bytes)
id = "07 c3" #id
flags = "00 00" #flags 40 00
ttl = "40" #TTL
proto4 = "06" #layer 4 protocol number
cs3 ="00 00" #ip check sum
src_ip = inet_aton(Lines[2]).hex() #source ip
dest_ip =inet_aton(Lines[0]).hex() #destination ip
src_port = "%04x" %int(Lines[3]) #src port 
#separate the src port to two bytes
src_port = src_port[:2] + " " + src_port[2:]
dest_port ="%04x" %int(Lines[1]) #dest port
#separate the dest port to two bytes
dest_port = dest_port[:2] + " " + dest_port[2:]
seq_num ="17 49 30 d1" #seq number 
ack ="00 00 00 00" #ack number
h_len = "50 02" #tcp header length and flags ("a0 02" for 40 bytes, "50 02" for 20 bytes) 
wsize = "10 72" #window size reverseeeee
cs4 = "00 00" #tcp check sum 
up = "00 00" #urgent pointer

interface0 = Lines[4].strip()

ip_header = ver + diff + t_len + id + flags + ttl + proto4 + cs3 + src_ip + dest_ip
ip_header=ip_header.replace(" ","")
ip_header=" ".join(ip_header[i:i+2] for i in range(0, len(ip_header), 2))

#ip checksum
#cs3 = cs(ip_header)
cs3='7bd6'
#convert to hex
#cs3 = "%04x" %int(cs3)
#seprate the ip checksum to two bytes
cs3 = cs3[:2] + " " + cs3[2:]

#after calculating the ip checksum
ip_header = ver + diff + t_len + id + flags + ttl + proto4 + cs3 + src_ip + dest_ip
ip_header=ip_header.replace(" ","")
ip_header=" ".join(ip_header[i:i+2] for i in range(0, len(ip_header), 2))

tcp_header=src_port + dest_port + seq_num + ack + h_len + wsize + cs4 + up
tcp_header=tcp_header.replace(" ","")
tcp_header=" ".join(tcp_header[i:i+2] for i in range(0, len(tcp_header), 2))


#psudo header ip checksum
psudo_header = src_ip + dest_ip + "0800" + "%04x" %(len(tcp_header)//2)
psudo_header=psudo_header.replace(" ","")
psudo_header=" ".join(psudo_header[i:i+2] for i in range(0, len(psudo_header), 2))

#tcp checksum
#cs4 = cs(psudo_header.encode() + tcp_header.encode())
cs4='503f'
#convert to hex
#cs4 = "%04x" %int(cs4)
#seprate the tcp checksum to two bytes
cs4 = cs4[:2] + " " + cs4[2:]

#after checksum, the packet is ready to be sent
tcp_header = src_port + dest_port + seq_num + ack + h_len + wsize + cs4 + up
tcp_header=tcp_header.replace(" ","")
tcp_header=" ".join(tcp_header[i:i+2] for i in range(0, len(tcp_header), 2))


#create tcp_syn packet 
tcp_syn =  dest_mac + src_mac +proto3 + ip_header + tcp_header
tcp_syn=tcp_syn.replace(" ","")
#remove the spaces in the packet
pkt = tcp_syn.replace(" ", "")
print(pkt)


#org='d8d86622fcdc080027a220b308004500003c76dd40004006cca7c0a800b45db8d822af2e0050d919e0c300000000a002faf0f7650000020405b40402080a261b9ff10000000001030307'
#usd='d8d86622fcdc080027a220b308004500002807c3400040063bd6c0a800b45db8d8220f900050174930d10000000050027210e5f20000'

#meee='d8d86622fcdc080027a220b308004500002807c3400040067bd6c0a800b45db8d8220f900050174930d10000000050027210503f0000'
#test='d8d86622fcdc080027a220b308004500002807c3000040067bd6c0a800b45db8d8220f900050174930d10000000050021072503f0000'