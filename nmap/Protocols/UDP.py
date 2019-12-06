import struct, copy
from Misc.Tools import Tools
from Protocols.IP import IP

class UDP(object):
    def __init__(self, Source_Port, Destination_Port, Length = None, Data = bytes(0), Checksum = None):
        if Length == None: Length = 8 + len(Data) #(Cabecera: 8 bytes) + Datos

        self.Source_Port = Source_Port              # 2 Bytes -> 16 bits
        self.Destination_Port = Destination_Port    # 2 Bytes -> 16 bits
        self.Length = Length                        # 2 Bytes -> 16 bits
        self.Checksum = Checksum                    # 2 Bytes -> 16 bits
        self.Data = Data

    @staticmethod
    def from_bytes(data):
        #Desempaquetando bytes del segmento UDP
        Bytes = struct.unpack("!HHHH", data[0:8])
        
        #Devolviendo objeto UDP con los datos desempaquetados
        return UDP(
            Source_Port = Bytes[0],         # 2 Bytes -> 16 bits
            Destination_Port = Bytes[1],    # 2 Bytes -> 16 bits
            Length = Bytes[2],              # 2 Bytes -> 16 bits
            Checksum = Bytes[3],            # 2 Bytes -> 16 bits
            Data = data[8:]
        )

    #Devuelve un nuevo objeto UDP con los mismos valores.
    def copy(self):
        return copy.deepcopy(self)

    def to_bytes(self, IP_H:IP):    
        Checksum = self.Checksum
            
        if (Checksum == None):
            #Obteniendo pseudocabecera IP
            Pseudo_IPHeader = IP_H.getPseudoHeader(self.Length)

            #Obteniendo copia de objeto UDP
            UDP_COPY = self.copy()
            UDP_COPY.Checksum = 0 # 0 para forzar el calculo del checksum

            #Calculando checksum (Pseudo cabecera IP + Cabecera UDP + Datos)
            Checksum = Tools.Checksum(Pseudo_IPHeader + UDP_COPY.to_bytes(None))
        
        #Empaquetando segmento y devolviendolo
        return struct.pack("!HHHH",
            self.Source_Port,        # 2 Bytes -> 16 bits
            self.Destination_Port,   # 2 Bytes -> 16 bits
            self.Length,             # 2 Bytes -> 16 bits
            Checksum            # 2 Bytes -> 16 bits
        ) + self.Data