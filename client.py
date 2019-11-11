import socket, sys
from socket import AF_PACKET, SOCK_RAW
from struct import *

def sendeth(eth_frame, interface = "enp4s0"):
	"""Send raw Ethernet packet on interface."""
	s = socket.socket(AF_PACKET, SOCK_RAW)
	s.bind((interface, 0))
	return s.send(eth_frame)

def checksum(msg):
	s = 0
	# loop taking 2 characters at a time
	for i in range(0, len(msg), 2):
		w = (msg[i] << 8) + (msg[i+1])
		s = s + w

	s = (s >> 16) + (s & 0xffff);
	s = ~s & 0xffff

	return s

def get_mac_addr(bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        mac_addr = ':'.join(bytes_str).upper()
        return mac_addr

def unpack_eth_header(data):
        dst_mac, src_mac, proto = unpack('!6s6sH', data)
        return get_mac_addr(dst_mac),get_mac_addr(src_mac), socket.htons(proto), data[:14]



if __name__ == "__main__":
	# src=fe:ed:fa:ce:be:ef, dst=52:54:00:12:35:02, type=0x0800 (IP)
	dst_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
	src_mac = [0x00, 0x0a, 0x11, 0x11, 0x22, 0x22]
	
	# Ethernet header
	eth_header = pack('!6B6BH', dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5], 
		src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], 0x0800)
	
	source_ip = '192.168.1.101'
	dest_ip = '192.168.1.1'			# or socket.gethostbyname('www.google.com')
	 



	


##########################################
##					 #
##	    IP HEADER PACKET	         #
##					 #
##########################################
	# ip header fields
	ihl = 5
	version = 4
	ihl_version = (version << 4) + ihl
	tos = 0
	tot_len = 20 + 8 + 512
	id = 54321  #Id of this packet
	frag_off = 0
	ttl = 255
	protocol = socket.IPPROTO_UDP
	check = 0
	saddr = socket.inet_aton(source_ip)
	daddr = socket.inet_aton(dest_ip)
	
	# the ! in the pack format string means network order
	ip_header = pack('!BBHHHBBH4s4s' , ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
	check = checksum(ip_header)
	
	# build the final ip header (with checksum)
	ip_header = pack('!BBHHHBBH4s4s' , ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)

	 
##########################################
##					 #
##	    CREATE UDP PACKET	         #
##					 #
##########################################
	
	src_port = 1234
	dst_port = 5678
	data_length = 520
	checksum = 0

	udp_header = pack('!HHHH',src_port,dst_port,data_length, checksum)


	# pseudo header fields
	source_address = socket.inet_aton( source_ip )
	dest_address = socket.inet_aton(dest_ip)
	placeholder = 0
	protocol = socket.IPPROTO_UDP
	udp_length = len(udp_header)
	 
	psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , udp_length);
	psh = psh + udp_header;
	f = open('log.txt','rb')
	l = f.read(512)
####3 GET FILE


	#f = open('log.txt','rb')
   	#l = f.read(512)

#### FALTA checksum(psh) agora
### Adicionar o correto checksum no header


##########################################
##					 #
##	    SEND DATA		         #
##					 #
########################################## 
	# final full packet - syn packets dont have any data
	packet = eth_header + ip_header + udp_header + l
	r = sendeth(packet, "enp4s0")
	
	print("Sent %d bytes" % r)

	state = 0
	while (1):
		if (state == 0): # AGUARDA REQUEST
			s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
			s.bind(("enp4s0", 0))
			raw_packet, addr = s.recvfrom(65535)
			print (addr)
			recv_dst_mac, recv_src_mac, recv_eth_proto, recv_data_eth = unpack_eth_header(raw_packet[:14])
			print (recv_src_mac)
		#if (state == 1): # ENVIA 512 BYTES
		#if (state == 2): # AGUARDA ACK
