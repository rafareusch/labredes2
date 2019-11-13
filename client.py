#made this
def unpack_ipv4(data): ##return header ipv4
    header = unpack('!BBHHHBBHII',packet[14:34]) #[14:34] intervalo header
    ip_src = '.'.join(map(str, header[8])) #ip_source
    ip_dst = '.'.join(map(str, header[9])) #ip_dest
    return header, ip_src, ip_dst

# Unpack IPv4 Packets Recieved
def ipv4_Packet(data): #Got this from https://github.com/O-Luhishi/Python-Packet-Sniffer/blob/master/Packet-Sniffer.py
    ttl, proto, src, target = unpack('!8xBB2x4s4s', data[:20])
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    #ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]

def unpack_udp(data): #Got this from https://github.com/O-Luhishi/Python-Packet-Sniffer/blob/master/Packet-Sniffer.py
    src_port, dest_port, size = unpack('!HH2xH', data[:8])
    return src_port, dest_port, size, data[8:]
