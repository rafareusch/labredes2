############ PAYLOAD HEADER

- 1 BYTE - Seq Number
- 1 BYTE - ACK field (if none, set all zeros)
- 1 BYTE - Last packet
- 1 BYTE - Send technique (?????)



############ Client Role:
- Should use the same send funcion of the server

1 > Send request to server
      - request => set ACK = 0
                   set Seq = 0
                   send
                   go to state 2
                   
2 > Listen for the data coming from server
     - when received => do a ipv4 checksum and see if the value equals to the received checksum in ipv4 header
                              if equal
                                       Send ACK back to server correctly ( very important to send seq_number correctly)       
                                       write payload data to file
                                       Stay at state 2
                              if not equal
                                       Discard packet and wait for the retransmit
                        if it is the last packet => goto state 4 
     
     - when timeout => Back to state 1
                                         

4 > Use mkd5sum to check integrity of the data received
      end program.


Process to unpack all data ( the order must be followed)
1) unpack eth header, see if dst_mac is your mac, if not, listen to next message
2) unpack ip header         (this wont change)
3) unpack udp header        (this wont change)                             
4) unpack payload header    (this probably will be changed)


(Must NOT do steps 2,3,4 if step 1 is not true)



############ Server Role:
