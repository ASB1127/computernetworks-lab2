import packet
class MRTBase:
    def _send_packet(self, packet):
        raw = str(packet).encode()
        self.sock.sendto(raw, self.dst)

    def _is_checksum_valid(self, received_packet):
        received_checksum = int(received_packet.checksum)
        expected_checksum = received_packet.calculateChecksum()
        return received_checksum == expected_checksum
