############ PAYLOAD HEADER

- 1 BYTE - Seq Number
- 1 BYTE - ACK field (if none, set all zeros)
- 1 BYTE - Send technique (??)\



############ Client Role:
- Should use the same send funcion of the server

1 > Send request to server
      - request => ACK = 0
                   Last Seq = 0

2 > Listen for the data coming from server
     - when received => do a ipv4 checksum and see if the value equals to the received checksum
                             Send ACK back to server correctly ( very important to send seq_number correctly)       
                             write payload data to file
                             Stay at state 2
                        if ipv4 checksum /= received cheksum
                             Discard packet and wait for the retransmit
                        when last_packet => goto state 4
     
     - when timeout => Back to state 1
                                         

4 > Use mkd5sum to check integrity of the data received


Process to unpack all data
1) unpack eth header, see if dst_mac is your mac   (done)
2) unpack ip header
3) unpack udp header                                
4) unpack payload header


############ Server Role:
