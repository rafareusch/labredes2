import socket, sys
import stat
import os
import time
import ipaddress
import hashlib
import requests
import operator
import functools
from socket import AF_PACKET, SOCK_RAW
from struct import *

interface = "enp3s0"
dst_mac = [0x00, 0x0a, 0xf7, 0x2b, 0x69, 0x49]
src_mac = [0xa4, 0x1F, 0x72, 0xF5, 0x90, 0x52]


def unpack_eth_header(data):
        dst_mac, src_mac, proto = unpack('!6s6sH', data[:14])
        return dst_mac,src_mac, socket.htons(proto), data[:14]

def unpack_udp_sub_header(data):
	    sub_seq_number,sub_ack_field,sub_lastpacket,sub_send_mode,sub_checksum = unpack('!BBBBB', data[:5])
	    return sub_seq_number,sub_ack_field,sub_lastpacket,sub_send_mode,sub_checksum

def unpack_ipv4(data):
    ihl_version, tos, tot_len, id_ipv4, frag_off, ttl, protocol, check, source_ip, dest_ip = unpack('!BBHHHBBH4s4s',data[:20]) #pacote de 20 bytes
    return get_ipv4_addr(source_ip), get_ipv4_addr(dest_ip)

def unpack_udp(data):
    src_port, dest_port, size, checksum = unpack('!HHHH', data[:8]) #Pacote de 8 bytes
    return src_port, dest_port, size

def unpack_hash(data): #unpack hash tuple
    hash_data = unpack('!32s',data[:32])
    return hash_data

def get_ipv4_addr(bytes_addr): 
        return str(ipaddress.ip_address(bytes_addr))

def sendeth(eth_frame, interface):
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

def prepare_pack(source_ip,dest_ip,last_packet,ack,checksum_udp,sub_seq_number):
    
        eth_header = pack('!6B6BH', dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5], 
        src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], 0x0800)
        #print(len(eth_header))

        data_length = 13
        src_port = 9999
        dst_port = 4567
	
        udp_header = pack('!HHHH',src_port,dst_port,data_length, checksum_udp)	

        ihl = 5
        version = 4
        ihl_version = (version << 4) + ihl
        tos = 0
        tot_len = 20 + 8 + 5 # 20 ip 8 udp header 5 sub header 499 data
        id_j = 54321  #Id of this packet
        frag_off = 0
        ttl = 255
        protocol = socket.IPPROTO_UDP
        check = 0
        source_ip = socket.inet_aton(source_ip)
        dest_ip = socket.inet_aton(dest_ip)

        ip_header = pack('!BBHHHBBH4s4s' , ihl_version, tos, tot_len, id_j, frag_off, ttl, protocol, check, source_ip, dest_ip)
        check = checksum(ip_header)
        ip_header = pack('!BBHHHBBH4s4s' , ihl_version, tos, tot_len, id_j, frag_off, ttl, protocol, check, source_ip, dest_ip)

        sub_ack_field = ack
        sub_lastpacket = last_packet
        sub_send_mode = 0
        file_checksum = 0
        udp_sub_header = pack ('!BBBBB', sub_seq_number, sub_ack_field, sub_lastpacket,sub_send_mode,file_checksum)
        #print(hash_client)
        #hash_header = ('p',hash_client)

        packet = eth_header + ip_header + udp_header + udp_sub_header #+ hash_header

        send_pack = sendeth(packet, interface)
        #print("sent:",send_pack)

def deleteContent(fname):
    with open(fname,"w"):
        pass

def conv_hash(hash_bytes): ##function to convert tuple to byte then to string
    hash_server = functools.reduce(operator.add,(hash_bytes))
    hash_final = hash_server.decode("utf-8")
    return hash_final

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
  
if __name__ == "__main__":
    #f = open('log_2.txt','wb')
    source_ip = '10.32.143.215'
    dest_ip = '10.32.143.208'
    state = 0
    checksum_udp = 0
    lenght_data = 0
    received_seq = 0
    #hash_client = '903738b23b241ebecbdf62a14183e37f'
    #type(hash_client)
    #------------------------------------------------
    while(1):
        if(state == 0):
            f = open('log_2.txt','wb')
            print("Requesting to server")
            s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
            s.bind((interface,0))
            last_packet = 1
            ack = 1
            prepare_pack(source_ip,dest_ip,last_packet,ack,checksum_udp,0)
            state = 1
            #----------------------------------------
        if(state == 1):
            raw_packet, addr = s.recvfrom(65553)
            recv_dst_mac, recv_client_mac, recv_eth_proto, recv_data_eth = unpack_eth_header(raw_packet[:14])
            if (recv_eth_proto == 8):
                if(get_mac_addr(recv_dst_mac) == get_mac_addr(src_mac) and get_mac_addr(recv_client_mac) == get_mac_addr(dst_mac)):
                    up_client_ip, up_server_ip = unpack_ipv4(raw_packet[14:])
                    up_client_port, up_server_port,up_udp_size = unpack_udp(raw_packet[34:])

                    sub_seq_number,sub_ack_field,sub_lastpacket,sub_send_mode,sub_checksum = unpack_udp_sub_header(raw_packet[42:])
                    #hash_bytes = unpack_hash(raw_packet[47:]) #unpack hash tuple
                    data = raw_packet[79:]
                    #hash_final = conv_hash(hash_bytes) ##function to convert tuple to byte then to string
                    #------------------------------------------
                
                    print("\n-------------------Message received-------------")
                    print("Received SEQ",sub_seq_number)
                    print("Wanted   SEQ",received_seq)
                    print(data)
                    lenght_data = lenght_data + len(data)
                    #------------------------------------------
                    if(sub_lastpacket == 2):
                        deleteContent("log_2.txt")
                        print("RESET received")
                        received_seq = 0
                        time.sleep(2)
                        f.close()
                        state = 0
                    else:
                        #------------------------------------------
                        if(received_seq != sub_seq_number):
                            deleteContent("log_2.txt")
                            print("Seq_Number errado")
                            time.sleep(2)
                            received_seq = 0
                            f.close()
                            state = 0
                        if(received_seq == sub_seq_number):   
                            prepare_pack(source_ip,dest_ip,0,1,checksum_udp,sub_seq_number) 
                            received_seq = received_seq + 1
                            f.write(data)  

                        #------------------------------------------ 
                        if(sub_lastpacket == 1 ):
                            hash_bytes = unpack_hash(raw_packet[47:])
                            hash_final = conv_hash(hash_bytes)
                            f.close()
                            hash_teste = hash_final
                            hash_teste2 = md5Checksum("log_2.txt",None)
                            state = 2
                        
        #------------------------------------------------------
        if(state == 2):
            if(hash_teste == hash_teste2):
                print("Checksum correto")
                print(hash_final)
                print(md5Checksum("log_2.txt",None))
                break
            else:
                print("Checksum incorreto")
                print(hash_final)
                print(type(hash_final))
                print(md5Checksum("log_2.txt",None))
                print(type(md5Checksum("log_2.txt",None)))

                time.sleep(1)
                received_seq = 0
                #f = open('log_2.txt','wb')

                state = 0 #solicita novamente
            
