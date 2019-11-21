import socket, sys
from socket import AF_PACKET, SOCK_RAW
from struct import *
import ipaddress
from threading import Thread


interface_name = "enp0s3"

seq_to_send = 0
state = 0
send_ack = 0


class recv_thread(Thread):
	
	def __init__ (self, num):
		Thread.__init__(self)
		self.num = num
	def run(self):
		message_index = 0
		f = open('recv_log.txt','wb')
		thread_state = 1
		while(1):
			if (thread_state == 1): # SEARCH FOR ACK
				s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
				s.bind((interface_name, 0))
				raw_packet, addr = s.recvfrom(65535) # AUMENTAR?
				recv_dst_mac, recv_server_mac, recv_eth_proto, recv_data_eth = unpack_eth_header(raw_packet[:14])
				print ("\nThread -dst_mac index {}".format(recv_dst_mac))
				print ("Thread - src_mac index {}".format(get_mac_addr(src_mac)))
				if (recv_eth_proto == 8):
					if (get_mac_addr(src_mac) == (recv_dst_mac)):
						print ("--------------- Message Received")
						# Unpacking data
						up_client_ip, up_server_ip = unpack_ipv4(raw_packet[14:])
						up_client_port, up_server_port,up_udp_size = unpack_udp(raw_packet[34:])
						sub_seq_number,sub_ack_field,sub_lastpacket,sub_send_mode,sub_checksum = unpack_udp_sub_header(raw_packet[42:])

						print ("Thread - msg index {}".format(message_index))
						print ("Thread - seq index {}".format(sub_seq_number))

						#print(get_data_from_message(raw_packet[47:],up_udp_size))
						if (sub_seq_number == message_index):
							message_index = message_index + 1
							index = up_udp_size - 8 - 5 
							print(raw_packet[47:index])
							f.write(raw_packet[47:index])
							seq_to_send = message_index
							send_ack = 1
							# ack = 1
							# seq = sub_seq_number

						else:
							#erro
							f.close()
							thread_state = 0
							# ack = 0
							# seq = message_index
						

def checksum(msg):
	s = 0
	# loop taking 2 characters at a time
	for i in range(0, len(msg), 2):
		w = (msg[i] << 8) + (msg[i+1])
		s = s + w

	s = (s >> 16) + (s & 0xffff);
	s = ~s & 0xffff

	return s



				

def sendeth(eth_frame, interface = interface_name):
	"""Send raw Ethernet packet on interface."""
	s = socket.socket(AF_PACKET, SOCK_RAW)
	s.bind((interface, 0))
	return s.send(eth_frame)



def get_mac_addr(bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        mac_addr = ':'.join(bytes_str).upper()
        return mac_addr

def get_ipv4_addr(bytes_addr):
        return str(ipaddress.ip_address(bytes_addr))

def unpack_eth_header(data):
        dst_mac, src_mac, proto = unpack('!6s6sH', data)
        return get_mac_addr(dst_mac),get_mac_addr(src_mac), socket.htons(proto), data[:14]

def unpack_ipv4(data):
    ihl_version, tos, tot_len, id_ipv4, frag_off, ttl, protocol, check, source_ip, dest_ip = unpack('!BBHHHBBH4s4s',data[:20]) #pacote de 20 bytes = 160 bits
    return get_ipv4_addr(source_ip), get_ipv4_addr(dest_ip)

def unpack_udp(data):
    src_port, dest_port, size, checksum = unpack('!HHHH', data[:8]) #Pacote de 8 bytes = 64 bits
    return src_port, dest_port, size

def unpack_udp_sub_header(data):
	sub_seq_number,sub_ack_field,sub_lastpacket,sub_send_mode,sub_checksum = unpack('!BBBBB', data[:5])
	return sub_seq_number,sub_ack_field,sub_lastpacket,sub_send_mode,sub_checksum



dst_mac = [0x00, 0x0a, 0x11, 0x11, 0x22, 0x22]
src_mac = [0xFF, 0xFF, 0xFF, 0x11, 0x22, 0x22]



def send_message(sub_ack_field,sub_lastpacket,sub_send_mode,sub_seq_number):

	


	# src=fe:ed:fa:ce:be:ef, dst=52:54:00:12:35:02, type=0x0800 (IP)
	dst_mac = [0x00, 0x0a, 0x11, 0x11, 0x22, 0x22]
	src_mac = [0xFF, 0xFF, 0xFF, 0x11, 0x22, 0x22]

	# Ethernet header
	eth_header = pack('!6B6BH', dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
		src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], 0x0800)

	source_ip = '255.255.1.101'
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
	tot_len = 20 + 8 + 5
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
	data_length = 13
	udp_checksum = 0

	udp_header = pack('!HHHH',src_port,dst_port,data_length, udp_checksum)


	# pseudo header fields
	source_address = socket.inet_aton( source_ip )
	dest_address = socket.inet_aton(dest_ip)
	placeholder = 0
	protocol = socket.IPPROTO_UDP
	udp_length = len(udp_header)

	psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , udp_length);
	psh = psh + udp_header;



	file_checksum = 255 #md5sum('log.txt') FALTA ISSO AINDA
	udp_sub_header = pack ('!BBBBB', sub_seq_number, sub_ack_field, sub_lastpacket,sub_send_mode,file_checksum)

####3 GET FILE


	#f = open('log.txt','rb')
   	#l = f.read(512)

#### FALTA checksum(psh) agora
### Adicionar o correto checksum no header


##########################################
##					 #
##	    SEND DATA		         #
##					 #


	packet = eth_header + ip_header + udp_header + udp_sub_header
	r = sendeth(packet, interface_name)

	print("Sent %d bytes" % r)


if __name__ == "__main__":
	a = recv_thread(1)
	a.start()
	send_message(1,1,0,0)
	
	while(1):
		if (state == 0):
			if(send_ack == 1):
				send_message(1,0,0,seq_to_send)
				send_ack = 0

		
