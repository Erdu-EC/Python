import sys, struct, socket, copy
from Misc.Tools import Tools

class ICMP(object):
    def __init__(self, Type, Code, ID = 0, Sequence = 0, Data = bytes(0), Checksum = None):
        self.Type = Type            # 1 Byte
        self.Code = Code            # 1 Byte
        self.Checksum = Checksum    # Checksum -> 2 Bytes
        self.ID = ID                # 2 Bytes
        self.Sequence = Sequence    # 2 Bytes
        self.Data = Data

    def to_bytes(self):
        Checksum = self.Checksum

        if (Checksum == None):
            Checksum = Tools.Checksum(
                ICMP(
                    self.Type,
                    self.Code,
                    self.ID,
                    self.Sequence,
                    self.Data,
                    0 # 0 para forzar el calculo del checksum.
                ).to_bytes()
            )

        return struct.pack("!BBHHH",
            self.Type,      # 1 Byte
            self.Code,      # 1 Byte
            Checksum,       # 2 Bytes
            self.ID,        # 2 Bytes
            self.Sequence,  # 2 Bytes
        ) + self.Data
    
    #Establece el ID, el cual se reinicia al llegar al valor maximo.
    def setID(self):
        self.ID = (self.ID + 1) % 65536
    
    #Establece el N° Secuencia, el cual se reinicia al llegar al valor maximo.
    def setSequence(self):
        self.Sequence = (self.Sequence + 1) % 65536

    #Devuelve un nuevo objeto ICMP con los mismos valores.
    def copy(self):
        return copy.deepcopy(self)

    @staticmethod
    def from_bytes(data):
        Bytes = struct.unpack("!BBHHH", data[0:8])
        
        return ICMP(
            Type = Bytes[0],
            Code = Bytes[1],
            Checksum = Bytes[2],
            ID = Bytes[3],
            Sequence = Bytes[4],
            Data = data[8:]
        )

'''
class ICMP_NET(object):
    def receive(self):
        pass
'''