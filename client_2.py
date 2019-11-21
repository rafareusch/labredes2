import socket, sys
from socket import AF_PACKET, SOCK_RAW
from struct import *

def unpack_ipv4(data):
    ihl_version, tos, tot_len, id_ipv4, frag_off, ttl, protocol, check, source_ip, dest_ip = unpack('!BBHHHBBH4s4s',data[:20]) #pacote de 20 bytes = 160 bits
    return ihl_version, tos, tot_len, id_ipv4, frag_off, ttl, protocol, check, source_ip, dest_ip
def unpack_udp(data): 
    src_port, dest_port, size, checksum = unpack('!HHHH', data[:8]) #Pacote de 8 bytes = 64 bits
    return src_port, dest_port, size, checksum

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

def prepare_pack(source_ip,dest_ip,file_size,checksum_udp):
    
        dst_mac = [0x00, 0x0a, 0x11, 0x11, 0x22, 0x22]
        src_mac = [0xFF, 0xFF, 0xFF, 0x11, 0x22, 0x22]

        eth_header = pack('!6B6BH', dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5], 
        src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], 0x0800)
        print(unpack_eth_header(eth_header))

        data_length = file_size + 8
        src_port = 1234
        dst_port = 5678
	
        udp_header = pack('!HHHH',src_port,dst_port,data_length, checksum_udp)	
        print(len(udp_header))
        print(unpack_udp(udp_header))

        ihl = 5
        version = 4
        ihl_version = (version << 4) + ihl
        tos = 0
        tot_len = 20 + 8 + 512
        id_j = 54321  #Id of this packet
        frag_off = 0
        ttl = 255
        protocol = socket.IPPROTO_UDP
        check = 0
        source_ip = socket.inet_aton(source_ip)
        dest_ip = socket.inet_aton(dest_ip)

        ip_header = pack('!BBHHHBBH4s4s' , ihl_version, tos, tot_len, id_j, frag_off, ttl, protocol, check, source_ip, dest_ip)
    
        packet = eth_header + udp_header + ip_header
        
        send_pack = sendeth(packet, "enp4s0")
        print("sent %d bytes" % send_pack)

    
if __name__ == "__main__":
    
    f = open('log.txt','rb')
    file_size = os.stat('log.txt')
	file_size = file_size.st_size
    
    source_ip = '192.168.1.101'
	dest_ip = '192.168.1.1'
    
    received_packets = 0
    state = 0
    fast_mode = 0
    
    dst_mac = [0x00, 0x0a, 0x11, 0x11, 0x22, 0x22]
	src_mac = [0xFF, 0xFF, 0xFF, 0x11, 0x22, 0x22]

	src_port = 1234
	dst_port = 5678

	checksum_udp = 0
	

    while(1){
        if(state == 0):
            print("Requesting to server")
            s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
            s.bind(("enp4s0",0))
            prepare_pack(source_ip,dest_ip,file_size,src_port,dst_port,checksum_udp)
            raw_packet = s.recvfrom(65535)
            recv_dst_mac, recv_src_mac, recv_eth_proto, recv_data_eth = unpack_eth_header(raw_packet[:14])
            state = 1
        if(state == 1): #receber os bytes
        if(state == 2):
    }
