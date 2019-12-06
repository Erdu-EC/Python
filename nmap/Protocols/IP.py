import sys, struct, socket, copy
from ipaddress import IPv4Address
from random import randint

class IP(object):
    def __init__(
            self, ID, Protocol, Source_IP, Destination_IP,
            Version = 4,
            Long_head = 5,
            Service_type = 28,
            Long_datagram = 0,
            DF = 0, MF = 0, Offset = 0,
            TTL = 64,
            Checksum = 0,
            Data = bytes(0)
        ):

        self.Version = Version                              # 4 bits
        self.Long_head = Long_head                          # 4 bits
        self.Type_Service = Service_type                    # 1 Byte -> 8 bits
        self.Long_datagram = Long_datagram                  # 2 Bytes -> 16 bits
        self.ID = ID                                        # 2 Bytes -> 16 bits
        self.DF = DF                                        # 1 bit
        self.MF = MF                                        # 1 bit
        self.Offset = Offset                                # 13 bits
        self.TTL = TTL                                      # 1 Byte -> 8 bits
        self.Protocol = Protocol                            # 1 Byte -> 8 bits
        self.Checksum = Checksum                            # 2 Bytes -> 16 bits
        self.Source_IP = IPv4Address(Source_IP)             # 4 Bytes -> 32 bits
        self.Destination_IP = IPv4Address(Destination_IP)   # 4 Bytes -> 32 bits
        self.Data = Data

    def getPseudoHeader(self, Packet_lenght):
        return struct.pack("!4s4sBBH",
            self.Source_IP.packed,
            self.Destination_IP.packed,
            0,
            self.Protocol,
            Packet_lenght
        )

    def to_bytes(self):
        return struct.pack("!BBHHHBBHLL",
            (self.Version << 4) + self.Long_head,   #Version (4) y Longitud cabecera (5 * 4 bytes = 20)
            self.Type_Service,                      #Tipo se servicio (000 111 00) - 28
            self.Long_datagram,                     #Longitud del datagrama (No se especifica)
            self.ID,                                #ID del datagrama
            (self.DF << 14) + (self.MF << 13) + self.Offset,
            self.TTL,
            self.Protocol,
            self.Checksum,                          #Checksum (No se especifica)
            int(self.Source_IP),
            int(self.Destination_IP)
        ) + self.Data

    #Establecer el ID, el cual se reinicia al llegar al valor maximo.
    def setID(self):
        self.ID = (self.ID + 1) % 65536

    def setRandomID(self):
        self.ID = randint(0,65535) # 2 Bytes

    #Devuelve una copia completa del objeto
    def copy(self):
        return copy.deepcopy(self)

    @staticmethod
    def from_bytes(data):
        Bytes = struct.unpack("!BBHHHBBH4s4s", data[0:20])
        
        return IP(
            Version = Bytes[0] >> 4,        # 4 bits
            Long_head = Bytes[0] & 15,      # 4 bits
            Service_type = Bytes[1],        # 1 Byte -> 8 bits
            Long_datagram = Bytes[2],       # 2 Bytes -> 16 bits
            ID = Bytes[3],                  # 2 Bytes -> 16 bits
            DF = (Bytes[4] >> 14) & 1,      # 1 bit
            MF = (Bytes[4] >> 13) & 1,      # 1 bit
            Offset = Bytes[4] & 8191,       # 13 bits
            TTL = Bytes[5],                 # 1 Byte -> 8 bits
            Protocol = Bytes[6],            # 1 Byte -> 8 bits
            Checksum = Bytes[7],            # 2 Bytes -> 16 bits
            Source_IP = Bytes[8],           # 4 Bytes -> 32 bits
            Destination_IP = Bytes[9],      # 4 Bytes -> 32 bits
            Data = data[20:]
        )
