# 
# Columbia University - CSEE 4119 Computer Networks
# Assignment 2 - Mini Reliable Transport Protocol
#
# mrt_client.py - defining client APIs of the mini reliable transport 
# protocol
#

import socket # for UDP connection
import threading
import packet
from mrt_common import MRTBase
from packet_logger import PacketLogger


class Client(MRTBase):
    def init(self, src_port, dst_addr, dst_port, segment_size):
        """
        initialize the client and create the client UDP channel

        arguments:
        src_port -- the port the client is using to send segments
        dst_addr -- the address of the server/network simulator
        dst_port -- the port of the server/network simulator
        segment_size -- the maximum size of a segment (including the header)
        """
        self.src_port = src_port
        self.dst_addr = dst_addr
        self.dst_port = dst_port
        self.dst = (dst_addr, dst_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", src_port))
        self.sock.settimeout(0.2)

        self.state = "CLOSED"
        self.connected_event = threading.Event()   
        self.closed_event = threading.Event()
        self.logger = PacketLogger(f"client_log_{self.src_port}.txt")
             
        self.segment_size = segment_size
        
        self.t_recv = threading.Thread(
            target=self.rcv_and_sgmnt_handler,
            daemon=False,
        )
        self.t_recv.start()
        
    def rcv_and_sgmnt_handler(self):
        while True:
            try:
                raw_packet, addr = self.sock.recvfrom(self.segment_size)
            except socket.timeout:
                continue
            pkt = packet.PacketFactory.parse(raw_packet.decode())
            #if the checksum of the packet comes out invalid drop the packet
            if not self._is_checksum_valid(pkt):
                self.logger.log_drop(pkt, "checksum did not pass")
                continue
            #if not same source address then not a valid packet
            if addr != self.dst:
                self.logger.log_drop(pkt, "addr did not match")
                continue
            #Checking if the SYN_ACk is received
            if self.state == "SYN_SENT" and pkt.type == packet.Packet.SYN_ACK:
                ack_packet = packet.PacketFactory.createACKFamilyPacket(
                    packet.Packet.ACK,
                    seq=1,
                    ackNum=pkt.seq,
                    rwnd=-1,
                )
                #sending the ack for the SYN_ACK
                self._send_packet(ack_packet)
                #logging send packet
                self.logger.log_send(ack_packet)
                #setting connection state
                self.state = "ESTABLISHED"
                self.connected_event.set()
                #At this point the connection is established
            
            if self.state == "FIN_SENT" and pkt.type == packet.Packet.FIN_ACK:
                ack_packet = packet.PacketFactory.createACKFamilyPacket(
                    packet.Packet.ACK,
                    seq=101,
                    ackNum=pkt.seq,
                    rwnd=-1,
                )
                self._send_packet(ack_packet)
                self.logger.log_send(ack_packet)
                self.state = "CLOSED"
                self.closed_event.set()
                break
                

    def connect(self):
        """
        connect to the server
        blocking until the connection is established

        it should support protection against segment loss/corruption/reordering 
        """
        self.connected_event.clear()
        self.state = "SYN_SENT"
        syn_packet = packet.PacketFactory.createSynPacket(seq=0)
        self._send_packet(syn_packet)
        self.logger.log_send(syn_packet)
        self.connected_event.wait()
        
        
        

    def send(self, data):
        """
        send a chunk of data of arbitrary size to the server
        blocking until all data is sent

        it should support protection against segment loss/corruption/reordering and flow control

        arguments:
        data -- the bytes to be sent to the server
        """
        pass

    def close(self):
        """
        request to close the connection with the server
        blocking until the connection is closed
        """
        self.closed_event.clear()
        self.state = "FIN_SENT"
        fin_packet = packet.PacketFactory.createFinPacket(seq=100)
        self._send_packet(fin_packet)
        self.logger.log_send(fin_packet)
        self.closed_event.wait()
        
