def unpack_ipv4(data): ##return header ipv4
    bits_packet_1 = unpack('!BBHHHBBH4s4s',data[:20]) #pacote de 20 bytes = 160 bits
    header = "{:32b}".format(bits_packet_1) ##para poder manipular bit a bit
    ihl_version = header[0:7]
    tos = header[8:15]
    tot_len = header[16:31]
    id_ipv4 = header[32:47]
    flags = header[48:50] ##nao usamos no pacote, mas caso precise ja esta aqui
    frag_off = header[51:63] 
    ttl = header[64:71]
    protocol = header[72:79]
    check = header[80:95]
    saddr = header[96:127]
    daddr = header[128:159]
    return ihl_version, tos, tot_len, id_ipv4, frag_off, ttl, protocol, check, saddr, daddr 

def unpack_udp(data): 
    bits_packet_1 = unpack('!HHHH', data[:64]) #Pacote de 8 bytes = 64 bits
    header = "{:32b}".format(bits_packet_1) ##como no ipv4, manipular bit a bit
    src_port = header[0:15]
    dest_port = header[16:31]
    size = header[32:47]
    checksum = header[48:63]
    return src_port, dest_port, size, checksum
