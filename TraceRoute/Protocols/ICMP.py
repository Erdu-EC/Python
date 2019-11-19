import sys, socket

class ICMP(object):    

    def __init__(self, Packet = bytes()):
        self.Type = Packet[0] # 1 Byte -> 8 bits
        self.Code = Packet[1] # 1 Byte -> 8 bits
        self.Checksum = (Packet[2] << 8) + Packet[3] # 2 Bytes -> 16 bits
        self.Data = Packet[8:] # N Bytes