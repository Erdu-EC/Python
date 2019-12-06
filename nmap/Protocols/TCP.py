import struct, copy
from Misc.Tools import Tools
from Protocols.IP import IP

class TCP(object):
    def __init__(self, Source_Port, Destination_Port,
        Sequence = 0, Sequence_ACK = 0, Header_Length = 20,
        URG = 0, ACK = 0, PSH = 0,
        RST = 0, SYN = 0, FIN = 0,
        Window = 100, Pointer = 0,
        Data = bytes(0),  Checksum = None
    ):
        self.Source_Port = Source_Port              # 2 Bytes -> 16 bits
        self.Destination_Port = Destination_Port    # 2 Bytes -> 16 bits
        self.Sequence = Sequence                    # 4 Bytes -> 32 bits
        self.Sequence_ACK = Sequence_ACK            # 4 Bytes -> 32 bits
        self.Header_Length = Header_Length          # 4 bits (Defecto: 20 Bytes)
                                                    # 6 bits sin usar
        self.Flag_URG = URG                         # 1 bits
        self.Flag_ACK = ACK                         # 1 bits
        self.Flag_PSH = PSH                         # 1 bits
        self.Flag_RST = RST                         # 1 bits
        self.Flag_SYN = SYN                         # 1 bits
        self.Flag_FIN = FIN                         # 1 bits
        self.Announced_Window = Window    # 2 Bytes -> 16 bits (Defecto: 100 bytes)
        self.Checksum = Checksum                    # 2 Bytes -> 16 bits
        self.Urg_Pointer = Pointer              # 2 Bytes -> 16 bits
        self.Data = Data

    #Funcion que pone a cero todos los flags
    def setZeroFlag(self):
        self.Flag_ACK = 0
        self.Flag_FIN = 0
        self.Flag_PSH = 0
        self.Flag_RST = 0
        self.Flag_SYN = 0
        self.Flag_URG = 0

    def setSequence(self):
        self.Sequence = (self.Sequence + 1) % (2**32)

    def to_bytes(self, IP_HEADER:IP):
        Checksum = self.Checksum

        if (Checksum == None):
            #Longitud del segmento TCP (Cabecera + Datos)
            Length = self.Header_Length + len(self.Data)

            #Obteniendo pseudocabecera IP
            Pseudo_IPHeader = IP_HEADER.getPseudoHeader(Length)

            #Obteniendo copia objeto TCP y modificando campos
            TCP_COPY = self.copy()
            TCP_COPY.Checksum = 0 #Forzar el calculo del checksum

            #Calculando checksum (Pseudo cabecera IP + Cabecera TCP + Datos)
            Checksum = Tools.Checksum(Pseudo_IPHeader + TCP_COPY.to_bytes(None))
        
        #Empaquetando segmento y devolviendolo
        return struct.pack("!HHLLBBHHH",
            self.Source_Port,        # 2 Bytes -> 16 bits
            self.Destination_Port,   # 2 Bytes -> 16 bits
            self.Sequence,           # 4 Bytes -> 32 bits
            self.Sequence_ACK,       # 4 Bytes -> 32 bits
            (int((self.Header_Length / 4)) << 4),   # 1 Bytes -> 4 bits + 4 bits sin usar
            (
                             # 2 bits sin usar
                (self.Flag_URG << 5) + # 1 bits
                (self.Flag_ACK << 4) + # 1 bits
                (self.Flag_PSH << 3) + # 1 bits
                (self.Flag_RST << 2) + # 1 bits
                (self.Flag_SYN << 1) + # 1 bits
                (self.Flag_FIN)        # 1 bits
            ),
            self.Announced_Window,             # 2 Bytes -> 16 bits
            Checksum,           # 2 Bytes -> 16 bits
            self.Urg_Pointer,            # 2 Bytes -> 16 bits
        ) + self.Data

    #Devuelve un nuevo objeto TCP con los mismos valores.
    def copy(self):
        return copy.deepcopy(self)

    @staticmethod
    def from_bytes(data:bytes):
        #Desempaquetando bytes del segmento UDP
        Bytes = struct.unpack("!HHLLBBHHH", data[0:20])
        
        #Devolviendo objeto UDP con los datos desempaquetados
        return TCP(
            Source_Port = Bytes[0],             # 2 Bytes -> 16 bits
            Destination_Port = Bytes[1],        # 2 Bytes -> 16 bits
            Sequence = Bytes[2],                # 4 Bytes -> 32 bits
            Sequence_ACK =  Bytes[3],           # 4 Bytes -> 32 bits
            Header_Length = Bytes[4] >> 4,      # 4 bits
            URG = (Bytes[5] & 32) >> 5,    # 1 bits
            ACK = (Bytes[5] & 16) >> 4,    # 1 bits
            PSH = (Bytes[5] & 8) >> 3,     # 1 bits
            RST = (Bytes[5] & 4) >> 2,     # 1 bits
            SYN = (Bytes[5] & 2) >> 1,     # 1 bits
            FIN = (Bytes[5] & 1),          # 1 bits
            Window = Bytes[6],        # 2 Bytes -> 16 bits
            Checksum = Bytes[7],                # 2 Bytes -> 16 bits
            Pointer = Bytes[8],             # 2 Bytes -> 16 bits
            Data = data[20:]
        )