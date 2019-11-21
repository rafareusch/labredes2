import socket, sys
from socket import AF_PACKET, SOCK_RAW
from struct import *
import os
import ipaddress
import time
#import md5sum

interface_name = "enp0s3"
thread_state = 0
from threading import Thread

class recv_thread(Thread):
	def __init__ (self, num):
		Thread.__init__(self)
		self.num = num
	def run(self):
		while(1):
			if (thread_state == 1): # SEARCH FOR ACK
				s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
				s.bind((interface_name, 0))
				raw_packet, addr = s.recvfrom(65535) # AUMENTAR?
				up_client_ip, up_server_ip = unpack_ipv4(raw_packet[14:])
				print ("Thread - client ip: {}".format(up_client_ip))
				print ("Thread - server ip: {}".format(up_server_ip))
			#if (thread_state == 2): # SEARCH FOR ACK




def sendeth(eth_frame, interface = interface_name):
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

	s = (s >> 16) + (s & 0xffff)
	s = ~s & 0xffff

	return s

def get_mac_addr(bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        mac_addr = ':'.join(bytes_str).upper()
        return mac_addr

def unpack_eth_header(data):
        dst_mac, src_mac, proto = unpack('!6s6sH', data)
        return dst_mac,src_mac, socket.htons(proto), data[:14]

def unpack_ipv4(data):
    ihl_version, tos, tot_len, id_ipv4, frag_off, ttl, protocol, check, source_ip, dest_ip = unpack('!BBHHHBBH4s4s',data[:20]) #pacote de 20 bytes = 160 bits
    return get_ipv4_addr(source_ip), get_ipv4_addr(dest_ip)
def unpack_udp(data):
    src_port, dest_port, size, checksum = unpack('!HHHH', data[:8]) #Pacote de 8 bytes = 64 bits
    return src_port, dest_port, size

def get_ipv4_addr(bytes_addr):
        return str(ipaddress.ip_address(bytes_addr))

def unpack_udp_sub_header(data):
	sub_seq_number,sub_ack_field,sub_lastpacket,sub_send_mode,sub_checksum = unpack('!BBBBB', data[:5])
	return sub_seq_number,sub_ack_field,sub_lastpacket,sub_send_mode,sub_checksum

#def unpack_ipv4_header(data):

#def unpack_udp_header(data):

#def unpack_udp_subheader(data):


def prepare_packet(dst_mac,src_mac,dest_ip,file_data,udp_send_mode,udp_seq_number,udp_ackfield,udp_lastpacket,file_size):

	# src=fe:ed:fa:ce:be:ef, dst=52:54:00:12:35:02, type=0x0800 (IP)


	# Ethernet header
	eth_header = pack('!6B6BH', dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
		src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], 0x0800)

	source_ip = '192.168.1.101'
				# or socket.gethostbyname('www.google.com')







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
	tot_len = 20 + 8 + 5 + file_size
	id = 54321  #Id of this packet
	frag_off = 0
	ttl = 255
	protocol = socket.IPPROTO_UDP
	check = 0
	saddr = socket.inet_aton(source_ip)
	daddr = socket.inet_aton(dest_ip)

	# the ! in the pack format string means network order
	ip_header = pack('!BBHHHBBH4s4s' , ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
	check =  checksum(ip_header)
	print (check)
	# build the final ip header (with checksum)
	ip_header = pack('!BBHHHBBH4s4s' , ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)


##########################################
##					 #
##	    CREATE UDP PACKET	         #
##					 #
##########################################

	src_port = 4567
	dst_port = 9999
	data_length = file_size + 8
	checksum_udp = 0

	udp_header = pack('!HHHH',src_port,dst_port,data_length, checksum_udp)


	# pseudo header fields
	source_address = socket.inet_aton( source_ip )
	dest_address = socket.inet_aton(dest_ip)
	placeholder = 0
	protocol = socket.IPPROTO_UDP
	udp_length = len(udp_header)

	psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , udp_length)
	psh = psh + udp_header


#### FALTA checksum(psh) agora
### Adicionar o correto checksum no header


	sub_ack_field = udp_ackfield
	sub_lastpacket = udp_lastpacket
	sub_send_mode = udp_send_mode
	sub_seq_number = udp_seq_number
	file_checksum = 255 #md5sum('log.txt') FALTA ISSO AINDA
	udp_sub_header = pack ('!BBBBB', sub_seq_number, sub_ack_field, sub_lastpacket,sub_send_mode,file_checksum)

								    #///			512                 \\\
	          #   14           20          8           5                499
	packet = eth_header + ip_header + udp_header + udp_sub_header + file_data
	r = sendeth(packet, interface_name)

	print("Sent %d bytes" % r)
	print ("len:{}".format(len(udp_sub_header)))
	print ("len:{}".format(len(file_data)))


if __name__ == "__main__":

	state = 0
	sent_packets = 0
	fast_mode = 0
	MAX_SIZE_MESSAGE = 499
	a = recv_thread(1)
	a.start()

	#dst_mac = [0xFF, 0x0a, 0xFF, 0x11, 0xFF, 0x22]
	src_mac = [0x00, 0x0a, 0x11, 0x11, 0x22, 0x22]
	dest_ip = '255.168.1.1'


	print ("Waiting for request packet")
	
	while (1):
		if (state == 0): # AGUARDA REQUEST
			thread_state = 0
			s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
			s.bind((interface_name, 0))
			raw_packet, addr = s.recvfrom(65535) # AUMENTAR?
			#print (addr)
			recv_dst_mac, recv_client_mac, recv_eth_proto, recv_data_eth = unpack_eth_header(raw_packet[:14])
			#print (recv_dst_mac, recv_eth_proto)
			if (recv_eth_proto == 8):
				if (get_mac_addr(src_mac) == get_mac_addr(recv_dst_mac)):
					print ("--------------- Message Received")

					# Unpacking data
					up_client_ip, up_server_ip = unpack_ipv4(raw_packet[14:])
					up_client_ip, up_server_ip = unpack_ipv4(raw_packet[14:])
					up_client_port, up_server_port,up_udp_size = unpack_udp(raw_packet[34:])
					sub_seq_number,sub_ack_field,sub_lastpacket,sub_send_mode,sub_checksum = unpack_udp_sub_header(raw_packet[42:])

					# Testing if message is a request
					sent_packets = 0
					if (sub_lastpacket == 1 and sub_ack_field == 1):
						print ("----- It is a request packet ------ Conection Estabilished")
						state = 1
						thread_state = 0
						f = open('log.txt','rb')
						 # Thread start
						
					else:
						print ("------ Request packet incorrect")
					# printing debug data
					print ("seq {}".format(sub_seq_number))
					print ("ack {}".format(sub_ack_field))
					print ("sub_checksum {}".format(sub_checksum))
					print ("client port: {}".format(up_server_port))
					print ("recv server port: {}".format(recv_dst_mac))
					print ("recv client port: {}".format(recv_client_mac))
					file_size = os.stat('log.txt')
					file_size = file_size.st_size
					total_num_packets = (int)(file_size/MAX_SIZE_MESSAGE)
					


		if (state == 1):# ENVIA 512 BYTES
			# unpack id header
			# IF FAST MODE = 1
			# IF FAST MODE = 2
			time.sleep(1)
			print ("\n")
			print ("##########################  NEW DATA FRAGMENT ")
			file_data = f.read(MAX_SIZE_MESSAGE)
			print(file_data)
			print ("len:{}".format(len(file_data)))
			print ("packet n:{}".format(sent_packets))
			print ("packet n:{}".format(total_num_packets))
			if (sent_packets == total_num_packets):
				last_packet_flag = 1
				f.close()
			else:
				last_packet_flag = 0

			prepare_packet(recv_client_mac,src_mac,dest_ip,file_data,fast_mode,sent_packets,0,last_packet_flag,len(file_data))

			sent_packets = sent_packets + 1

			if (last_packet_flag == 1):
				state = 0


		if (state == 2): # AGUARDA ACK
			print("WAIT ACK")
