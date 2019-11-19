import sys, socket

class IP(object):  

    def __init__(self, IPPacket = bytes()):
        #for byte in IPPacket:
         #   for i in range(0,8):
          #      bit = (byte & 128) >> 7
           #     byte = (byte & 127) << 1
            #    print(bit, end='')
            #print(" ", end='')
        #print("\n")

        self.version = IPPacket[0] >> 4 # 4 bits
        self.longitud_head = (IPPacket[0] & 15) # 4 bits
        self.servicio = IPPacket[1] # 1 Byte -> 8 bits
        self.longitud_trama = (IPPacket[2] << 8) + IPPacket[3] # 2 Bytes -> 16 bits
        self.identificador = (IPPacket[4] << 8) + IPPacket[5] # 2 Bytes -> 16 bits
        self.DontFragment = (IPPacket[6] & 64) >> 6 # 1 bit
        self.MoreFragment = (IPPacket[6] & 32) >> 5 # 1 bit
        self.OffsetFragment = ((IPPacket[6] & 31) << 8) + IPPacket[7] # 13 bits
        self.TTL = IPPacket[8] # 1 Byte -> 8 bits
        self.Protocol = IPPacket[9] # 1 Byte -> 8 bits
        self.Checksum = (IPPacket[10] << 8) + IPPacket[11] # 2 Bytes -> 16 bits
        self.SourceAddress = (IPPacket[12] << 24) + (IPPacket[13] << 16) + (IPPacket[14] << 8) + IPPacket[15] # 4 Bytes -> 32 bits
        self.DestinationAddress = (IPPacket[16] << 24) + (IPPacket[17] << 16) + (IPPacket[18] << 8) + IPPacket[19] # 4 Bytes -> 32 bits

        #FALTA GESTIONAR CAMPO DE OPCIONES DE LA CABECERA DEL DATAGRAMA IP

        #DATOS UTILES
        self.Data = IPPacket[20:]

    def getSourceAddress(self):
        return socket.inet_ntoa(self.SourceAddress.to_bytes(4, 'big'))

    def getDestinationAddress(self):
        return socket.inet_ntoa(self.DestinationAddress.to_bytes(4, 'big'))