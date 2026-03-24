"""
ACK, DATA, SYN, FIN, FIN_ACK, SYN_ACK

SEQ | TYPE | CHECKSUM | ?ACK_NUM | ?RWND | ?DATA

has ACK_NUM:  ACK, FIN_ACK, SYN_ACK
has RWND: ACK, SYN_ACK
has DATA: DATA
"""
import base64
import zlib
class Packet:
    
    DELIM = "|"
    TAB = "\t"
    ACK = "ACK"
    SYN = "SYN"
    FIN = "FIN"
    FIN_ACK = "FIN_ACK"
    SYN_ACK = "SYN_ACK"
    DATA = "DATA"
    LOG_COLUMNS = ["SEQ", "TYPE", "CHECKSUM", "ACK_NUM", "RWND", "DATA_LEN"]
    LOG_WIDTHS = {"SEQ": 8, "TYPE": 10, "CHECKSUM": 16, "ACK_NUM": 8, "RWND": 8, "DATA_LEN": 8}
    
    FLDS = {"TYPE": 0, "SEQ": 1, "CHECKSUM": 2}

    
    def __init__(self, type, seq,checksum):
        self.seq = int(seq)
        self.type = type
        self.checksum = int(checksum)
        
    def __str__(self):
        return f"{self.type}{Packet.TAB}{self.seq}{Packet.TAB}{self.checksum}"
    
    def setChecksum(self, checksum):
        self.checksum = checksum
        
    def parse(self, packetData):
        flds = packetData.split(Packet.DELIM)
        return flds
    def getFlds(self):
        return {"TYPE":self.type, "SEQ":self.seq, "CHECKSUM":self.checksum} 

    def calculateChecksum(self):
        flds = self.getFlds()
        del flds["CHECKSUM"]
        res = "".join([str(value) for value in flds.values()])

        return zlib.crc32(res.encode())

    @staticmethod
    def getHeaderStr():
        return "".join(f"{col:<{Packet.LOG_WIDTHS[col]}}" for col in Packet.LOG_COLUMNS).rstrip()

    def getLogStr(self):
        flds = self.getFlds()
        row = {
            "SEQ": flds.get("SEQ", ""),
            "TYPE": flds.get("TYPE", ""),
            "CHECKSUM": flds.get("CHECKSUM", ""),
            "ACK_NUM": flds.get("ACK_NUM", ""),
            "RWND": flds.get("RWND", ""),
            "DATA_LEN": "",
        }

        if "DATA" in flds:
            row["DATA_LEN"] = len(flds["DATA"])

        return "".join(
            f"{str(row[col]):<{Packet.LOG_WIDTHS[col]}}" for col in Packet.LOG_COLUMNS
        ).rstrip()

        
        
class SynPacket(Packet):
    def __init__(self, seq, checksum):
        super().__init__(Packet.SYN,seq,checksum)
        
    def getFlds(self):
        flds = super().getFlds()
        return flds
        
class FinPacket(Packet):
    def __init__(self, seq, checksum):
        super().__init__(Packet.FIN,seq,checksum)
    def getFlds(self):
        return super().getFlds()  
class DataPacket(Packet):
    def __init__(self, seq, checksum, data):
        super().__init__(Packet.DATA,seq, checksum)
        self.data = data
    def getFlds(self):
        flds = super().getFlds()
        flds["DATA"]=self.data 
        return flds
    def __str__(self):
        str = super().__str__()
        encoded_data = base64.b64encode(self.data).decode("ascii")
        return f"{str}{Packet.TAB}{encoded_data}"

class AckPacket(Packet):
    def __init__(self, seq, checksum, ackNum, rwnd):
        super().__init__(Packet.ACK,seq, checksum)
        self.ackNum = int(ackNum)
        self.rwnd = int(rwnd)

    def getFlds(self):
        flds = super().getFlds()
        flds["ACK_NUM"] = self.ackNum
        flds["RWND"] = self.rwnd
        return flds
        
    def __str__(self):
        str = super().__str__()
        return f"{str}{Packet.TAB}{ self.ackNum}{Packet.TAB}{self.rwnd}"
class FinAckPacket(Packet):
    def __init__(self, seq, checksum, ackNum):
        super().__init__(Packet.FIN_ACK, seq, checksum)
        self.ackNum = int(ackNum)
    def getFlds(self):
        flds =super().getFlds()
        flds["ACK_NUM"] = self.ackNum
        return flds  
    def __str__(self):
        str = super().__str__()
        return f"{str}{Packet.TAB}{ self.ackNum}"
        
class SynAckPacket(Packet):
    def __init__(self, seq, checksum, ackNum, rwnd):
        super().__init__(Packet.SYN_ACK,seq, checksum)
        self.ackNum = int(ackNum)
        self.rwnd = int(rwnd)
    def getFlds(self):
        flds =super().getFlds()
        flds["ACK_NUM"] = self.ackNum
        flds["RWND"] = self.rwnd
        return flds
    def __str__(self):
        str = super().__str__()
        return f"{str}{Packet.TAB}{ self.ackNum}{Packet.TAB}{self.rwnd}"
        
class PacketFactory:
    
    def createACKFamilyPacket( packetType, seq, ackNum, rwnd=None):
        if packetType == Packet.ACK:
            p = AckPacket(seq, checksum=-1, ackNum=ackNum, rwnd=rwnd)
            p.setChecksum(p.calculateChecksum())
            return p
        elif packetType == Packet.FIN_ACK:
            p = FinAckPacket(seq, checksum=-1, ackNum=ackNum)
            p.setChecksum(p.calculateChecksum())
            return p
        elif packetType == Packet.SYN_ACK:
            p = SynAckPacket(seq, checksum=-1,ackNum=ackNum, rwnd=rwnd)
            p.setChecksum(p.calculateChecksum())
            return p
    
    def createDataPacket(seq,packetData):
        p=DataPacket(seq, checksum=-1, data=packetData)
        p.setChecksum(p.calculateChecksum())
        return p
    
    def createFinPacket(seq):
        p=FinPacket(seq, checksum=-1)
        p.setChecksum(p.calculateChecksum())
        return p
    
    def createSynPacket(seq):
        p = SynPacket(seq, checksum=-1)
        p.setChecksum(p.calculateChecksum())
        return p

        
    def parse(packetData):
        flds = packetData.split(Packet.TAB)
        type = flds[Packet.FLDS["TYPE"]]
        seq = flds[Packet.FLDS["SEQ"]]
        checksum = flds[Packet.FLDS["CHECKSUM"]]

        if type == Packet.ACK:
            ackNum = flds[3]
            rwnd = flds[4]
            return AckPacket(seq, checksum, ackNum=ackNum, rwnd=rwnd)
        elif type == Packet.DATA:
            data = base64.b64decode(flds[3].encode("ascii"))
            return DataPacket(seq, checksum, data=data)
        elif type == Packet.FIN:
            return FinPacket(seq, checksum)
        elif type == Packet.FIN_ACK:
            return FinAckPacket(seq, checksum, ackNum=flds[3])
        elif type == Packet.SYN:
            return SynPacket(seq, checksum)
        elif type == Packet.SYN_ACK:
            return SynAckPacket(seq, checksum, ackNum=flds[3], rwnd=flds[4])
        
        
if __name__ == "__main__":
    print(PacketFactory.parse("ACK\t1\t2\t3\t4096"))
    print(PacketFactory.parse("DATA\t1\t2\taGVsbG8="))
    print(PacketFactory.parse("FIN\t1\t2"))
    print(PacketFactory.parse("FIN_ACK\t1\t2\t3"))
    print(PacketFactory.parse("SYN\t1\t2"))
    print(PacketFactory.parse("SYN_ACK\t1\t2\t3\t4096")) 
    
    print(PacketFactory.createACKFamilyPacket(Packet.ACK,seq=1, ackNum=1, rwnd=4096))
    print(PacketFactory.createACKFamilyPacket(Packet.FIN_ACK, seq=1, ackNum=1))
    print(PacketFactory.createACKFamilyPacket(Packet.SYN_ACK, seq=1, ackNum=1, rwnd=4096))
    print(PacketFactory.createDataPacket(seq=1, packetData=b"hello"))
    print(PacketFactory.createFinPacket(seq=1))
    print(PacketFactory.createSynPacket(seq=1))
    
    print(Packet.getHeaderStr())
    print(PacketFactory.parse("ACK\t1\t2\t3\t4096").getLogStr())
    print(PacketFactory.parse("DATA\t1\t2\taGVsbG8=").getLogStr())
    print(PacketFactory.parse("FIN\t1\t2").getLogStr())
    print(PacketFactory.parse("FIN_ACK\t1\t2\t3").getLogStr())
    print(PacketFactory.parse("SYN\t1\t2").getLogStr())
    print(PacketFactory.parse("SYN_ACK\t1\t2\t3\t4096").getLogStr())
    
