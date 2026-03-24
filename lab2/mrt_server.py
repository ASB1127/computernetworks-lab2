# 
# Columbia University - CSEE 4119 Computer Networks
# Assignment 2 - Mini Reliable Transport Protocol
#
# mrt_server.py - defining server APIs of the mini reliable transport 
# protocol
#

import socket # for UDP connection
import threading
import packet
from mrt_common import MRTBase
from packet_logger import PacketLogger
from circular_buffer import CircularByteBuffer

#
# Server
#
class Server(MRTBase):
    def init(self, src_port, receive_buffer_size):
        """
        initialize the server, create the UDP connection, and configure the receive buffer

        arguments:
        src_port -- the port the server is using to receive segments
        receive_buffer_size -- the maximum size of the receive buffer
        """
        self.src_port = src_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", src_port))
        self.sock.settimeout(0.1)
        
        
        self.receive_buffer_size = receive_buffer_size
        self.receive_buffer = CircularByteBuffer(receive_buffer_size)
        self.data_buffer = bytearray()
        self.expected_seq_num = 0
        
        self.buffer_lock = threading.Lock()
        self.receive_cv = threading.Condition(self.buffer_lock)
        self.data_cv = threading.Condition(self.buffer_lock)
        
        self.state = "CLOSED"
        self.conn = None
        self.accepted_event = threading.Event()
        self.closed_event = threading.Event()
        self.logger = PacketLogger(f"server_log_{self.src_port}.txt")

        
        self.t_rcv = threading.Thread(target=self.rcv_handler, daemon=False)
        self.t_sgmnt = threading.Thread(target=self.sgmnt_handler, daemon=False)
        self.t_rcv.start()
        self.t_sgmnt.start()

    def rcv_handler(self):
        while True:
            try:
                raw_packet, addr = self.sock.recvfrom(self.receive_buffer_size)
            except socket.timeout:
                continue
            except OSError:
                break

            pkt = packet.PacketFactory.parse(raw_packet.decode())
            if not self._is_checksum_valid(pkt):
                self.logger.log_drop(pkt, "checksum did not pass")
                continue
            if self.conn is not None and addr != self.conn:
                self.logger.log_drop(pkt, "addr did not match")
                continue
            #checking to see if the client sent a syn
            if self.state == "LISTEN" and pkt.type == packet.Packet.SYN:
                self.conn = addr
                self.dst = addr
                
                # if so then create a syn ack packet
                syn_ack = packet.PacketFactory.createACKFamilyPacket(
                    packet.Packet.SYN_ACK,
                    seq=0,
                    ackNum=pkt.seq,
                    rwnd=self.receive_buffer_size,
                )
               
                #send the syn_ack packet and set the state of the server
                self._send_packet(syn_ack)
                self.logger.log_send(syn_ack) 
                self.state = "SYN_RCVD"

            elif self.state == "SYN_RCVD" and pkt.type == packet.Packet.ACK:
                #if the ack packet is received then the connection is established
                self.state = "ESTABLISHED"
                self.accepted_event.set()
            
            elif self.state == "ESTABLISHED" and pkt.type == packet.Packet.FIN:
                fin_ack = packet.PacketFactory.createACKFamilyPacket(
                    packet.Packet.FIN_ACK,
                    seq=101,
                    ackNum=pkt.seq,
                )
                self.logger.log_send(fin_ack)
                self.state = "FIN_RCVD"
                self._send_packet(fin_ack)
            elif self.state == "FIN_RCVD" and pkt.type == packet.Packet.ACK:
                self.state = "CLOSED"
                self.closed_event.set()
            
            #Check to see if the packet is a data packet
            elif self.state == "ESTABLISHED" and pkt.type == packet.Packet.DATA:
                with self.buffer_lock:
                    # how much free space is left in the circular buffer
                    free_space = self.receive_buffer.available_space()

                    # if the packet can fit in the buffer add it otherwise drop
                    if pkt.seq == self.expected_seq_num and len(pkt.data) <= free_space:
                        self.receive_buffer.write(pkt.data)
                        # they byte sequence number of the next expected packet
                        self.expected_seq_num += len(pkt.data)
                        self.receive_cv.notify_all()

                    ack_num = self.expected_seq_num
                    rwnd = self.receive_buffer.available_space()

                ack_pkt = packet.PacketFactory.createACKFamilyPacket(
                    packet.Packet.ACK,
                    seq=0,
                    ackNum=ack_num,
                    rwnd=rwnd,
                )
                self._send_packet(ack_pkt)
                self.logger.log_send(ack_pkt)
                  

                
    
    def sgmnt_handler(self):
        while True:
            with self.buffer_lock:
                # if the receive buffer is empty then wait
                while self.receive_buffer.available_data() == 0:
                    if self.state == "CLOSED":
                        return
                    self.receive_cv.wait()
                # read the data from the buffer
                chunk = self.receive_buffer.read(self.receive_buffer.available_data())
                self.data_buffer.extend(chunk)
                self.data_cv.notify_all()
    
    
    def accept(self):
        """
        accept a client request
        blocking until a client is accepted

        it should support protection against segment loss/corruption/reordering 

        return:
        the connection to the client 
        """
        self.accepted_event.clear()
        self.state = "LISTEN"
        self.accepted_event.wait()
        return self.conn

    def receive(self, conn, length):
        """
        receive data from the given client
        blocking until the requested amount of data is received
        
        it should support protection against segment loss/corruption/reordering 
        the client should never overwhelm the server given the receive buffer size

        arguments:
        conn -- the connection to the client
        length -- the number of bytes to receive

        return:
        data -- the bytes received from the client, guaranteed to be in its original order
        """
        with self.buffer_lock:
            # if not the number of bytes requested is available then wait
            while len(self.data_buffer) < length:
                self.data_cv.wait()
            # read the number of requested bytes of data from the buffer
            data = bytes(self.data_buffer[:length])
            del self.data_buffer[:length]
            return data

    def close(self):
        """
        close the server and the client if it is still connected
        blocking until the connection is closed
        """
        if self.state != "CLOSED":
            self.closed_event.wait()

        self.conn = None
        self.dst = None
        self.sock.close()
        self.logger.close()
