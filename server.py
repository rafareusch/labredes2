import socket, sys
from socket import AF_PACKET, SOCK_RAW
from struct import *
import os
import ipaddress
import time
import hashlib
#import md5sum

interface_name = "enp4s0"
thread_state = 0
from threading import Thread
seq_missing = None
last_packet_flag = 0
ack_seq_index = None
tries = 0


class recv_thread(Thread):
	
	def __init__ (self, num):
		Thread.__init__(self)
		self.num = num
		
	def run(self):
		global seq_missing
		global ack_seq_index

		ack_seq_index = 0
		s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
		s.bind((interface_name, 0))
		while(1):
			if (thread_state == 1): # SEARCH FOR ACK
				raw_packet, addr = s.recvfrom(65535) # AUMENTAR?
				recv_dst_mac, recv_client_mac, recv_eth_proto, recv_data_eth = unpack_eth_header(raw_packet[:14])
				if (recv_eth_proto == 8):
					if (get_mac_addr(src_mac) == get_mac_addr(recv_dst_mac)):
						sub_seq_number,sub_ack_field,sub_lastpacket,sub_send_mode,sub_checksum = unpack_udp_sub_header(raw_packet[42:])
						print("\n ************ THREAD INFO")
						print("Received seq",sub_seq_number)
						print("Wanted   seq",ack_seq_index)
						print("Ack",sub_ack_field)
						
						if (ack_seq_index != sub_seq_number and sub_ack_field == 1 and sub_lastpacket == 0):
							# CONTROLE DE ERRO, IR PARA SLOW START
							seq_missing = 1
							print("Ack not received:",ack_seq_index,"missing",seq_missing)
							

						if (ack_seq_index == sub_seq_number and sub_ack_field == 1 and sub_lastpacket == 0):
							print(">>>> ACK RECEIVED <<<< seq:",ack_seq_index)
							if(last_packet_flag == 1):
								print("#################################### Client confirm all data is received")
								ack_seq_index = -1
							else:
								ack_seq_index += 1



							

def set_seq_missing(x):
	seq_missing = x
	print("seq missing",seq_missing)


def sendeth(eth_frame, interface = interface_name):
	"""Send raw Ethernet packet on interface."""
	s = socket.socket(AF_PACKET, SOCK_RAW)
	s.bind((interface, 0))
	return s.send(eth_frame)

def md5Checksum(filepath,url):
    m = hashlib.md5()
    if url==None:
        with open(filepath,'rb') as fh:
            m = hashlib.md5()
            while True:
                data = fh.read(65536)
                if not data:
                    break
                m.update(data)
            return m.hexdigest()
    else:
        r=request.get(url)
        for data in r.iter_content(65536):
            m.update(data)
        return m.hexdigest()

def unpack_hash(data):
    hash_data = unpack('!32s',data[:32])
    return hash_data 

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


def prepare_packet(dst_mac,src_mac,dest_ip,file_data,udp_send_mode,udp_seq_number,udp_ackfield,udp_lastpacket,file_size,hash_verification):

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
	tot_len = 20 + 8 + 5 + 32 + file_size #32 bytes do hash (???) 
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
	file_checksum = 255 # md5Checksum('log.txt',None) 
	udp_sub_header =  pack('!BBBBB', sub_seq_number, sub_ack_field, sub_lastpacket,sub_send_mode,file_checksum)

	hash_header = pack('!32s',hash_verification)
								    #///			512                 \\\ 
	          #   14           20          8           5                32			467
	packet = eth_header + ip_header + udp_header + udp_sub_header + hash_header + file_data 
	r = sendeth(packet, interface_name) #Nao sei pq hash deu 32, testei  num programa fora com um arquivo diferente e deu 32bytes
	#print(hash_header)
	print("Sent %d bytes" % r)
	#print(file_data)
	#print ("len:{}".format(len(udp_sub_header)))
	#print ("len:{}".format(len(file_data)))

total_num_packets = 0
sent_packets = 0



FAST_SLEEP = 0.01
SLOW_SLEEP = 1
timeout_slow = 0.25


if __name__ == "__main__":
	if (len(sys.argv) < 2 or len(sys.argv) > 2):
		print ("\nUSAGE: sudo python3 server.py mode       ### mode = {1,2}  1-fast/2-slow\n")
		exit()
	state = 0
	MODE = int(sys.argv[1]) # 1 FAST   2 SLOW
	hash_byte = md5Checksum('log.txt',None)
	hash_ready = str.encode(hash_byte) #gera o hash do teu arquivo
	fast_mode = 0
	MAX_SIZE_MESSAGE = 467
	a = recv_thread(1)
	a.start()
	seq_missing = 0
	#dst_mac = [0xFF, 0x0a, 0xFF, 0x11, 0xFF, 0x22]
	src_mac = [0x00, 0x0a, 0x11, 0x11, 0x22, 0x22]
	dest_ip = '255.168.1.1'


	print ("Waiting for request packet, mode:",MODE)
	
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
						ack_seq_index = 0
						state = MODE
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
					


		if (state == 1): # FAST START
			time.sleep(FAST_SLEEP)

			
			if (seq_missing == 1): # erro no sequenciamento
				ack_seq_index = 0
				seq_missing = 0
				sent_packets = 0
				f.close
				MODE = 2
				f = open('log.txt','rb')
				print("\n********** SEQ error, Slow Start will be enabled")
				state = 5 
			else:
				print ("\n")
				print ("##########################  SENDING DATA (FAST MODE)   #############################")
				file_data = f.read(MAX_SIZE_MESSAGE)
				#print(file_data)
				#print ("len:{}".format(len(file_data)))
				print ("packet num:{}".format(sent_packets))
				print ("Total packets :{}".format(total_num_packets))
				if (sent_packets == total_num_packets):
					last_packet_flag = 1
					f.close()
				else:
					last_packet_flag = 0

				prepare_packet(recv_client_mac,src_mac,dest_ip,file_data,fast_mode,sent_packets,0,last_packet_flag,len(file_data),hash_ready)
				thread_state = MODE
				sent_packets = sent_packets + 1

				if (last_packet_flag == 1):
					print ("########################################### All data is sent, waiting for ACK confirmation")
					start_time = time.time()
					state = 4


		if (state == 2): # SLOW START`
			time.sleep(SLOW_SLEEP)
			print ("\n")
			print ("#############################  SENDING DATA  (SLOW MODE)   #######################")
			file_data = f.read(MAX_SIZE_MESSAGE)
			#print(file_data)
			print ("len:{}".format(len(file_data)))
			print ("packet num:{}".format(sent_packets))
			print ("Total packets :{}".format(total_num_packets))
			if (sent_packets == total_num_packets):
				last_packet_flag = 1
				
				f.close()
			else:
				last_packet_flag = 0

			prepare_packet(recv_client_mac,src_mac,dest_ip,file_data,fast_mode,sent_packets,0,last_packet_flag,len(file_data),hash_ready)
			thread_state = 2
			sent_packets = sent_packets + 1
			start_time = time.time()
			state = 3

		if (state == 3): # test ack
			
			raw_packet, addr = s.recvfrom(65535) # AUMENTAR?
			recv_dst_mac, recv_server_mac, recv_eth_proto, recv_data_eth = unpack_eth_header(raw_packet[:14])
			elapsed_time = time.time()- start_time
			
			if (elapsed_time >= timeout_slow):
				print(" \n >>>>>>>>>>>>>>>>>>>>>>>TIMEOUT ")
				print("\n\n\n")
				last_packet_flag = 0
				state = 5
				thread_state = 0
			else:
				if (recv_eth_proto == 8):
					#print (" server port: {}".format(get_mac_addr(src_mac)))
					#print ("recv client port: {}".format(get_mac_addr(recv_dst_mac)))
					if (get_mac_addr(src_mac) == get_mac_addr(recv_dst_mac)):
						up_client_ip, up_server_ip = unpack_ipv4(raw_packet[14:])
						up_client_port, up_server_port,up_udp_size = unpack_udp(raw_packet[34:])
						sub_seq_number,sub_ack_field,sub_lastpacket,sub_send_mode,sub_checksum = unpack_udp_sub_header(raw_packet[42:])
						print ("\n************* WAIT ACK INFO")
						
						print ("receivd seq:{}".format(sub_seq_number))
						print ("wanted  seq: {}".format(sent_packets-1))

						# controle de erro caso seq recebido diferente de sent packet
						if (sub_ack_field == 1 and sub_seq_number != sent_packets-1 and sub_lastpacket == 0):
							print (" >>> INCORRECT SEQ NUMBER <<<< ")
							state = 5


						if (sub_ack_field == 1 and sub_seq_number == sent_packets-1 and sub_lastpacket == 0):
							print(" >>> ACK RECEIVED <<< ")
							if (last_packet_flag == 1):
								print ("########################################### Client confirms all data is received, connection is now ended")
								print ("\n\n Ready for next connection")
								state = 0
							else:
								state = 2
		if (state == 4):
			elapsed_time = time.time()- start_time
			
			if (elapsed_time >= 2):
				print(" \n >>>>>>>>>>>TIMEOUT ")
				print("\n\n\nReady for next client")
				last_packet_flag = 0
				state = 5
				thread_state = 0
				f.close
				f = open('log.txt','rb')
			if(ack_seq_index == -1 and last_packet_flag == 1):
				print("\n\n\nReady for next client")
				last_packet_flag = 0
				state = 0
				thread_state = 0
				ack_seq_index = 0
				f.close
				f = open('log.txt','rb')
			#	a.stop()
		
		if (state == 5):
			
			if (tries == 1):
				print(" \n >>>>>>>>>>> tries exceeded ")
				print("\n\n\nReady for next client")
				last_packet_flag = 0
				state = 0
				thread_state = 0
				f.close()
				tries = 0
				f = open('log.txt','rb')
			else:
				f.close()
				f = open('log.txt','rb')
				file_data = f.read(MAX_SIZE_MESSAGE)
				prepare_packet(recv_client_mac,src_mac,dest_ip,file_data,fast_mode,sent_packets,0,2,len(file_data),hash_ready)
				# SEND LAST PACKET = 2 TO START COMM
				# SLEEP 
				# GOTO SEND PACKET
				state = 0
				tries += 1
				print("\n\n\n 	>>>>>>>>>>>>> RESET SENT")
				print("Retrying, ready for ack-request")
