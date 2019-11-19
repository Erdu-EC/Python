import sys, socket

class UDP(object):    

    def __init__(self, Packet = bytes()):
        self.SourcePort = (Packet[0] << 8) + Packet[1] # 2 Bytes -> 16 bits
        self.DestinationPort = (Packet[2] << 8) + Packet[3] # 2 Byres -> 16 bits
        self.Lenght = (Packet[4] << 8) + Packet[5] # 2 Bytes -> 16 bits
        self.Checksum = (Packet[6] << 8) + Packet[7] # 2 Bytes -> 16 bits
        self.Data = Packet[8:] # N Bytes