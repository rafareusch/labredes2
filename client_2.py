import socket, sys
from socket import AF_PACKET, SOCK_RAW
from struct import *

def unpack_ipv4(data):
    ihl_version, tos, tot_len, id_ipv4, frag_off, ttl, protocol, check = unpack('!BBHHHBBH',data[:12]) #pacote de 20 bytes = 160 bits
    #header = "{:32b}".format(bits_packet_1) ##para poder manipular bit a bit
    #ihl_version = header[0:8]
    #tos = header[8:16]
    #tot_len = header[16:32]
    #id_ipv4 = header[32:48]
    #flags = header[48:51] ##nao usamos no pacote, mas caso precise ja esta aqui
    #frag_off = header[51:64] 
    #ttl = header[64:72]
    #protocol = header[72:80]
    #check = header[80:96]
    #saddr = header[96:128]
    #daddr = header[128:160]
    return ihl_version, tos, tot_len, id_ipv4, frag_off, ttl, protocol, check
def unpack_udp(data): 
    src_port, dest_port, size, checksum = unpack('!HHHH', data[:8]) #Pacote de 8 bytes = 64 bits
    #header = "{:8b}".format(bits_packet_1) ##como no ipv4, manipular bit a bit
    #src_port = header[0:16]
    #dest_port = header[16:32]
    #size = header[32:48]
    #checksum = header[48:64]
    return src_port, dest_port, size, checksum

if __name__ == "__main__":
	
	src_port = 1234
	dst_port = 5678
	data_length = 520
	checksum_udp = 32423
	
	udp_header = pack('!HHHH',src_port,dst_port,data_length, checksum_udp)	
	print(len(udp_header))
	print(unpack_udp(udp_header))

	ihl = 5
	version = 4
	ihl_version = 2
	tos = 0
	tot_len = 20 + 8 + 512
	id_j = 54321  #Id of this packet
	frag_off = 0
	ttl = 255
	protocol = 2
	check = 0
	
	ip_header = pack('!BBHHHBBH' , ihl_version, tos, tot_len, id_j, frag_off, ttl, protocol, check)
	print(len(ip_header))
	print(unpack_ipv4(ip_header))

