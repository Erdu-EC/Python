import sys, netifaces
from ipaddress import IPv4Network, IPv4Address

class Tools(object):
    @staticmethod
    def Checksum(data:bytes):
        #Si el numero de bytes es impar, convertir a par rellenando con 0s.
        if (len(data) % 2 != 0):
            data += (0).to_bytes(1,sys.byteorder,signed = False)
        
        #Sumando palabras de 2 bytes (16 bits)
        suma = 0
        for i in range(0, len(data), 2):
            suma += (data[i] << 8) + data[i+1]

        #Truncando la suma a 16 bits y sumando el acarreo
        while (suma >> 16):
            suma =  (suma & 65535) + (suma >> 16)
		
        #Obteniendo el complemento a 1 de la suma
        return ~suma & 65535

    @staticmethod
    def getGateway(Network:IPv4Network):
        #Obteniendo lista de gateways
        gateways = netifaces.gateways()

        #Buscando gateway perteneciente a la misma red
        for address in gateways[netifaces.AF_INET]:
            if IPv4Address(address[0]) in Network:
                return (
                    address[0], # Address
                    address[1]  # Interface
                )

        #Obteniendo gateway por defecto
        if 'default' in gateways:
            if netifaces.AF_INET in gateways['default']:
                return (
                    gateways['default'][netifaces.AF_INET][0],  # Address
                    gateways['default'][netifaces.AF_INET][1]   # Interface
                )

        return None

    @staticmethod
    def get_MyIP(Network:IPv4Network):
        gateway_ip, gateway_if = Tools.getGateway(Network)

        address = netifaces.ifaddresses(gateway_if)

        if (netifaces.AF_INET in address) and len(address[netifaces.AF_INET]):
            if 'addr' in address[netifaces.AF_INET][0]:
                return (
                    address[netifaces.AF_INET][0]['addr'],
                    gateway_ip, gateway_if
                )
                
        return (None, gateway_ip, gateway_if)

    @staticmethod
    def get_time(time):
        if isinstance(time, str): return time

        if time < 1: #Milisegundos
            return str(round(time * 1000, 2)) + " ms"
        elif time <= 60: #Segundos
            return str(round(time, 2)) + " seg"
        else: #Minutos
            return str(round(time / 60, 2)) + " min"

    @staticmethod
    def getProtocol(port, protocol):
        if protocol == '?': return ('Desconocido', 'Sin descripcion')

        fichero = open('./Misc/nmap-services','r')

        line_str = '0'
        while len(line_str) > 0:
            line_str = fichero.readline()
            if line_str.startswith('#'): continue
        
            lista = line_str.split()
            if str(port) + '/' + protocol in lista:
                fichero.close()
                return (lista[0], " ".join(lista[4:]))
            
        fichero.close()
        return ('Desconocido', 'Sin descripcion')