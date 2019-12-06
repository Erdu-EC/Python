#Autor: Eduardo Eliezar Castillo Hernández
#Fecha: 06/12/2019

#Importando modulos generales
import socket, threading, copy

from select import select
from random import randint
from time import sleep, time
from ipaddress import IPv4Address, IPv4Network

#Importando modulos propios
from Misc.ThreadPool import ThreadPool
from Misc.Tools import Tools

#Importando protocolos
from Protocols.IP import IP
from Protocols.ICMP import ICMP
from Protocols.TCP import TCP
from Protocols.UDP import UDP

class Protocols(object):
    def __init__(self, my_ip, gateway_ip):
        #PLANTILLA DE PAQUETE IP
        self.IP = IP(
            ID = randint(0,65535), # 2 Bytes
            DF = 1,
            Service_type= 29,
            TTL = 64,
            Protocol = 0,
            Source_IP = my_ip,
            Destination_IP = gateway_ip
        )

        #PLANTILLA DE PAQUETE ICMP
        self.ICMP = ICMP(
            ID = randint(0,65535), # 2 Bytes
            Sequence = randint(0,65535), # 2 Bytes
            Type = 8,
            Code = 0,
        )

        #PLANTILLA DE PAQUETE TCP
        self.TCP = TCP(
            Source_Port = randint(4000, (2**16)-1), #4,000 - 65,535
            Destination_Port = 80,
            Sequence = randint(0, (2**32) - 1), # 4 Bytes -> 32 bits
            Window = 100,
        )

        #PLANTILLA DE PAQUETE UDP
        self.UDP = UDP(
            Source_Port = randint(4000, (2**16)-1), #4,000 - 65,535
            Destination_Port = 80
        )

class HostDetecter(object):
    def __init__(self, protocols:Protocols, max_retrans, timeout, simultaneous_host, max_host_detected):
        #Variables pasadas por comandos
        self.MAX_HOST_DETECTED = max_host_detected
        self.MAX_RETRANS = max_retrans
        self.SIMULTANEOUS_HOST = simultaneous_host
        self.TIME_OUT = timeout

        #Plantilla de protocolos
        self.protocols = protocols

        #Listas utilizadas
        self.icmp_wait_list = dict()
        self.icmp_ready_list = dict()

        self.tcp_wait_list = dict()
        self.tcp_ready_list = dict()

        '''
        self.udp_wait_list = dict()
        self.udp_ready_list = dict()
        '''

    def find(self, network:IPv4Network, tcp_port = 80):
        #Creando socket de envio
        sock_sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

        #Guardando tiempo de inicio
        time_start = time()

        #Lanzando hilo para recibir ICMP
        thread_icmp_event = threading.Event() #Creando evento para terminar el hilo
        thread_icmp = threading.Thread(
            target=self.receiveICMP, name = "Receive ICMP...", kwargs={
                'stop_event': thread_icmp_event,
                'type_waited': [0, 3]
            }
        )
        thread_icmp.start()

        #Lanzando hilo para recibir TCP
        thread_tcp_event = threading.Event() #Creando evento para terminar el hilo
        thread_tcp = threading.Thread(
            target=self.receiveTCP, name = "Receive TCP...", kwargs={
                'stop_event': thread_tcp_event,
                'source_address': self.protocols.IP.Source_IP,
                'source_port': self.protocols.TCP.Source_Port
            }
        )
        thread_tcp.start()

        #Obteniendo lista de host de la red
        host_list = network.hosts()

        #Recorriendo lista de hosts
        while True:
            #Si se ha superado el limite de host detectados
            if self.is_limit_detected(): break

            #Eligiendo host a detectar
            hosts = self.getHosts(host_list, self.SIMULTANEOUS_HOST)

            #Si no faltan host
            if hosts == None: break

            #Enviando ICMP a los host elegidos
            self.sendICMP(sock_sender, address_list = copy.deepcopy(hosts), type = 8, code = 0)

            #Enviando TCP a los host elegidos
            self.sendTCP(sock_sender, address_list = copy.deepcopy(hosts), SYN = 1, port = tcp_port)
       
        #Deteniendo hilo de recepcion ICMP
        thread_icmp_event.set()
        thread_icmp.join()

        #Deteniendo hilo de recepcion TCP
        thread_tcp_event.set()
        thread_tcp.join()

        #Calculando tiempo total
        time_rtt = time() - time_start

        #Cerrando socket de envio
        sock_sender.close()

        #Devolviendo resultados
        return {'TIME': time_rtt, 'ICMP': self.icmp_ready_list, 'TCP': self.tcp_ready_list}


    def sendICMP(self, sock_sender, address_list, type = 0, code = 0, num_sended = 1):
        #Verificando si se ha llegado al limite de retransmiciones
        if (num_sended > self.MAX_RETRANS): return

        #Protocolos utilizados
        IP = self.protocols.IP
        ICMP = self.protocols.ICMP

        #Campos cabecera IP
        IP.Protocol = socket.IPPROTO_ICMP

        #Campos cabecera ICMP
        ICMP.Type = type
        ICMP.Code = code

        #Inicializando contador de paquetes recibidos
        self.icmp_rcv_event = {
            'EVENT': threading.Event(), 'COUNT': 0, 'MAX': len(address_list)
        }

        #Recorriendo lista de host a enviar ICMP
        for dest_address in address_list:
            #Si se ha superado el limite de host detectados
            if self.is_limit_detected(): return

            #Campos cabecera IP
            IP.setID()
            IP.Destination_IP = dest_address

            #Campos cabecera ICMP
            ICMP.setID()
            ICMP.setSequence()
            
            #Enviando paquete
            sock_sender.sendto(IP.to_bytes() + ICMP.to_bytes(), (dest_address.exploded, 0))

            #Añadiendo paquetes a la lista de espera
            if (num_sended == 1): #Si es la primera vez que se envia
                time_start = time()
            else:
                if dest_address.exploded not in self.icmp_wait_list: continue

                time_start = self.icmp_wait_list[dest_address.exploded]['TIME']

            self.icmp_wait_list[dest_address.exploded] = {
                'SEND': num_sended,
                'TIME': time_start
            }

        #Si no se recibieron los tres paquetes antes de que se venciera el timeout
        if not self.icmp_rcv_event['EVENT'].wait(timeout=self.TIME_OUT * num_sended):
            #Obteniendo hosts aun pendientes
            address_list = self.getPendingHost(address_list, ICMP = True)

            if len(address_list) == 0: return

            #Retransmitir
            self.sendICMP(sock_sender, address_list, type, code, num_sended + 1)        

    def receiveICMP(self, stop_event:threading.Event, type_waited:list):
        Socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        #Mientras no se notifique la detencion
        while not stop_event.is_set():
            #Esperar por mensajes
            if len(select([Socket], [], [], self.TIME_OUT)[0]):
                #Leer mensajes
                data, address = Socket.recvfrom(80)
                address = address[0]

                #Guardando tiempo de recepcion
                time_rcv = time()

                #Desempaquetando ip recibido
                ip = IP.from_bytes(data)
                ip_address = ip.Source_IP.exploded

                #Desempaquetando icmp recibido
                icmp = ICMP.from_bytes(ip.Data)
                icmp_type = icmp.Type

                #Si no es de un tipo esperado
                if icmp_type not in type_waited:
                    continue

                if icmp_type == 3:
                    #Desempaquetando ip original
                    ip = IP.from_bytes(icmp.Data)
                    ip_address = ip.Destination_IP.exploded

                    #Desempaquetando icmp original
                    icmp = ICMP.from_bytes(ip.Data)

                #Eliminando variables temporales
                del icmp
                
                if ip.Protocol == socket.IPPROTO_ICMP:
                    #Si es una IP que no esta en lista de espera
                    if ip_address not in self.icmp_wait_list:
                        continue

                    #Obteniendo tiempo de envio del paquete
                    time_rtt = time_rcv - self.icmp_wait_list[ip_address]['TIME']
                    num_sended = self.icmp_wait_list[ip_address]['SEND']
                    
                    #Eliminandolo de la lista de espera
                    del self.icmp_wait_list[ip_address]

                    #Notificando la recepcion del paquete
                    self.icmp_rcv_event['COUNT'] += 1 #Aumentando contador de recibidos para esta IP

                    #Si se recibieron todos los paquetes enviados
                    if self.icmp_rcv_event['COUNT'] == self.icmp_rcv_event['MAX']:
                        self.icmp_rcv_event['EVENT'].set() #Activar evento

                    if icmp_type == 0:
                        #Agregando a la lista de host vivos
                        self.icmp_ready_list[ip_address] = {'RTT': time_rtt, 'SEND': num_sended}
                
                elif ip.Protocol == socket.IPPROTO_TCP:
                    if ip_address not in self.tcp_wait_list:
                        continue

                    #Eliminandolo de la lista de espera
                    del self.tcp_wait_list[ip_address]

                    #Notificando la recepcion del paquete
                    self.tcp_rcv_event['COUNT'] += 1 #Aumentando contador de recibidos para esta IP

                    #Si se recibieron todos los paquetes enviados
                    if self.tcp_rcv_event['COUNT'] == self.tcp_rcv_event['MAX']:
                        self.tcp_rcv_event['EVENT'].set() #Activar evento

            #Si se notifico la detencion
            if stop_event.is_set(): Socket.close()

    
    def sendTCP(self, sock_sender, address_list, SYN = 0, ACK = 0, port = 80, num_sended = 1):
        #Verificando si se ha llegado al limite de retransmiciones
        if (num_sended > self.MAX_RETRANS): return

        #Protocolos utilizados
        IP = self.protocols.IP
        TCP = self.protocols.TCP

        #Campos cabecera IP
        IP.Protocol = socket.IPPROTO_TCP

        #Campos cabecera TCP
        TCP.setZeroFlag()
        TCP.Flag_ACK = ACK
        TCP.Flag_SYN = SYN
        TCP.Destination_Port = port

        #Inicializando contador de paquetes recibidos
        self.tcp_rcv_event = {
            'EVENT': threading.Event(), 'COUNT': 0, 'MAX': len(address_list)
        }

        #Recorriendo lista de host a enviar TCP
        for dest_address in address_list:
            #Si se ha superado el limite de host detectados
            if self.is_limit_detected(): return

            #Campos cabecera IP
            IP.setID()
            IP.Destination_IP = dest_address

            #Campos cabecera TCP
            TCP.setSequence()
            
            #Enviando paquete
            sock_sender.sendto(IP.to_bytes() + TCP.to_bytes(IP), (dest_address.exploded, port))

            #Añadiendo paquetes a la lista de espera
            if (num_sended == 1): #Si es la primera vez que se envia
                time_start = time()
            else:
                if dest_address.exploded not in self.tcp_wait_list: continue
                try:
                    time_start = self.tcp_wait_list[dest_address.exploded]['TIME']
                except: continue

            self.tcp_wait_list[dest_address.exploded] = {
                'PORT': port,
                'SEND': num_sended,
                'TIME': time_start
            }

        #Si no se recibieron los tres paquetes antes de que se venciera el timeout
        if not self.tcp_rcv_event['EVENT'].wait(timeout=self.TIME_OUT * num_sended):
            #Obteniendo hosts aun pendientes
            address_list = self.getPendingHost(address_list, TCP = True)

            if len(address_list) == 0: return

            #Retransmitir
            self.sendTCP(sock_sender, address_list, SYN, ACK, port, num_sended + 1)

    def receiveTCP(self, stop_event:threading.Event, source_address, source_port):
        Socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        Socket.bind((source_address.exploded, source_port))
        Socket.setblocking(False)

        #Mientras no se notifique la detencion
        while not stop_event.is_set():
            #Esperar por mensajes
            if len(select([Socket], [], [], self.TIME_OUT)[0]):
                #Leer mensajes
                data, address = Socket.recvfrom(80)
                address = address[0]

                #Guardando tiempo de recepcion
                time_rcv = time()

                #Si es una IP que no esta en lista de espera
                if address not in self.tcp_wait_list:
                    continue

                #Desempaquetando ip recibido
                ip = IP.from_bytes(data)

                #Desempaquetando TCP recibido
                tcp = TCP.from_bytes(ip.Data)

                #Si es un tipo esperado de TCP
                if (tcp.Flag_SYN and tcp.Flag_ACK) or tcp.Flag_RST:
                    #Obteniendo tiempo de envio del paquete
                    time_rtt = time_rcv - self.tcp_wait_list[address]['TIME']
                    num_sended = self.tcp_wait_list[address]['SEND']

                    #Eliminandolo de la lista de espera
                    del self.tcp_wait_list[address]

                    #Notificando la recepcion del paquete
                    self.tcp_rcv_event['COUNT'] += 1 #Aumentando contador de recibidos para esta IP

                    #Si se recibieron todos los paquetes enviados
                    if self.tcp_rcv_event['COUNT'] == self.tcp_rcv_event['MAX']:
                        self.tcp_rcv_event['EVENT'].set() #Activar evento

                    #Agregando a la lista de host vivos
                    self.tcp_ready_list[address] = {'RTT': time_rtt, 'SEND': num_sended}

            #Si se notifico la detencion
            if stop_event.is_set(): Socket.close()

    #Funcion que determina la detencion del proceso de descubrimiento si se han detectado
    #el numero de host especificado por linea de comandos
    def is_limit_detected(self):
        if self.MAX_HOST_DETECTED == -1: return False

        return (len(self.icmp_ready_list) >= self.MAX_HOST_DETECTED) or (len(self.tcp_ready_list) >= self.MAX_HOST_DETECTED)


    def getHosts(self, host_list, max_host):
            hosts = []
            try:
                while max_host:
                    hosts += [next(host_list)]
                    max_host -= 1
            except StopIteration:
                if len(hosts) == 0:
                    return None

            return hosts

    def getPendingHost(self, host_list, ICMP = False, TCP = False, UDP = False):
        #Revisando que paquetes fueron recibidos
        for i in range(0, len(host_list)):
            host = host_list.pop() #Sacando de los host pendientes

            #Si todavia esta en la lista de espera
            if ICMP:
                packet_list = self.icmp_wait_list
            elif TCP:
                packet_list = self.tcp_wait_list
            else:
                packet_list = self.udp_wait_list

            if host.exploded in packet_list:
                host_list.insert(0, host) #Añadiendo a los puertos pendientes
        
        return host_list

class PortDetecter(object):
    def __init__(self, protocols, gateway, max_retrans, timeout, simultaneous_host, min_port, max_port):
        #Plantilla de protocolos
        self.protocols = protocols

        #Gateway del equipo anfitrion
        self.GATEWAY = gateway

        #Parametros de linea de comandos
        self.MAX_RETRANS = max_retrans
        self.TIME_OUT = timeout
        self.SIMULTANEOUS_HOST = simultaneous_host

        self.tcp_wait_list = dict()
        self.tcp_ready_list = dict()
        self.tcp_rcv_list = dict()

        self.udp_wait_list = dict()
        self.udp_ready_list = dict()
        self.udp_rcv_list = dict()

        #Cantidad de puertos a sondear simultaneamente
        self.TCP_SIMULTANEOUS_PORT = 50
        self.UDP_SIMULTANEOUS_PORT = 3
        #self.COUNT_SEND_PORT = 3

        #Rango de puertos a sondear
        self.MIN_PORT = min_port #0
        self.MAX_PORT = max_port #1025

    def probe(self, alive_list):
        #Protocolos utilizados
        IP = self.protocols.IP
        TCP = self.protocols.TCP
        UDP = self.protocols.UDP

        #Creando socket de envio
        self.sock_sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

        #Guardando tiempo de inicio
        time_start = time()

        #Creando objeto para controlar multiples hilos
        pool = ThreadPool((self.SIMULTANEOUS_HOST * 2) + 1)

        #Creando evento para controlar finalizacion de hilo ICMP
        thread_icmp_event = threading.Event() #Creando evento para terminar el hilo

        #Creando hilo receptor de mensajes ICMP
        thread_icmp = threading.Thread(target = self.receiveICMP, kwargs = {
                'stop_event': thread_icmp_event,
                'type_waited': [3],
                'code_waited': [1, 2, 3, 9, 10, 13]
            }, name = "Receive ICMP...")

        #Lanzando hilo icmp
        thread_icmp.start()

        #Recorriendo lista de host vivos
        for address in alive_list:
            #Creando objeto ipv4
            address = IPv4Address(address[0])

            #Modificando cabecera IP
            IP.setRandomID()
            IP.Destination_IP = address
            IP.Protocol = socket.IPPROTO_TCP

            #Lanzando hilo para un solo host (TCP)
            pool.addAction(action = self.detectTCP, args={
                'IP_H': IP.copy(),
                'TCP_H': TCP.copy(),
                'SYN': 1
            }, name = "TCP: " + address.exploded)

            #Modificando cabecera IP
            IP.setRandomID()
            IP.Protocol = socket.IPPROTO_UDP

            #Lanzando hilo para un solo host (UDP)
            pool.addAction(action = self.detectUDP, args={
                'IP': IP.copy(),
                'UDP': UDP.copy()
            }, name = "UDP: " + address.exploded)

            #Cambiando puerto utilizado
            TCP.Source_Port += 1

            if TCP.Source_Port > 65535:
                TCP.Source_Port = randint(4000, (2**16)-1), #4,000 - 65,535

        #Cerrando todos los hilos del controlador de hilos
        pool.close() #Notificar la detencion de todos los hilos y esperarlos.

        #Terminando hilo de recepcion icmp
        thread_icmp_event.set() #Notificar la detencion de hilo ICMP
        thread_icmp.join()

        #Cerrando socket de envio
        self.sock_sender.close()

        #Marcando puertos TCP sin respuesta como filtrados
        for address, port_list in self.tcp_wait_list.items():
            for port, data in port_list.items():
                self.tcp_ready_list[address][port] = {
                    'TYPE': 'tcp',
                    'STATE': PortStates.filtered,
                    'SEND': data['SEND'],
                    'RTT': '¿' + Tools.get_time(time() - data['TIME']) + '?'
                }

        #Marcando puertos UDP sin respuesta como filtrados
        for address, port_list in self.udp_wait_list.items():
            for port, data in port_list.items():
                self.udp_ready_list[address][port] = {
                    'TYPE': 'udp',
                    'STATE': PortStates.open_filtered,
                    'SEND': data['SEND'],
                    'RTT': '¿' + Tools.get_time(time() - data['TIME']) + '?'
                }

        #Calculando tiempo total
        time_rtt = time() - time_start

        #Devolviendo resultados
        return {'TIME': time_rtt, 'TCP': self.tcp_ready_list, 'UDP': self.udp_ready_list}

    def detectTCP(self, IP_H, TCP_H, ACK = 0, SYN = 0):
        #Campos cabecera IP
        IP_H.setID()

        #Campos cabecera TCP
        TCP_H.setZeroFlag()
        TCP_H.Flag_ACK = ACK
        TCP_H.Flag_SYN = SYN

        #variables necesarias
        source_address = IP_H.Source_IP.exploded
        dest_address = IP_H.Destination_IP.exploded

        #Inicializando entrada de las listas
        self.tcp_wait_list[dest_address] = {} #Lista de espera
        self.tcp_ready_list[dest_address] = {} #Lista de sondeados

        #Creando socket de recepcion
        SOCKET_RCV = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        SOCKET_RCV.setblocking(False)

        #Vincular al puerto que utilizamos para enviar
        SOCKET_RCV.bind((source_address, TCP_H.Source_Port)) 

        #Lanzando hilo de recepcion
        thread_rcv_finish = threading.Event() #Creando evento para terminar el hilo
        thread_rcv = threading.Thread(
            target=self.receiveTCP, name = "RCV TCP: " + dest_address, args=(
                thread_rcv_finish, SOCKET_RCV, dest_address
            )
        )
        thread_rcv.start()

        #Obteniendo lista de puertos
        range_ports = iter(range(self.MIN_PORT, self.MAX_PORT))

        #Recorriendo lista de puertos
        while True:
            #Eligiendo puertos a sondear
            port_list = self.getPorts(range_ports, self.TCP_SIMULTANEOUS_PORT) #2**16 de 100 en 100.

            #Si no faltan puertos
            if port_list == None: break

            #Enviando TCP a los puertos elegidos.
            self.sendTCP(IP_H, TCP_H, dest_address, port_list, num_sended = 1)

        #Esperando finalizacion del hilo de recepcion
        thread_rcv_finish.set()
        thread_rcv.join()
        
        #Marcando como filtrados los puertos sobrantes
        #TODO

        #Eliminando host de la lista de espera
        del self.tcp_wait_list[dest_address]

        #Cerrando socket de recepcion
        SOCKET_RCV.close()

    def sendTCP(self, IP, TCP, dest_address, port_list:list, num_sended):
        #Verificando si se ha llegado al limite de retransmiciones
        if (num_sended > self.MAX_RETRANS): return

        #Inicializando contador de paquetes recibidos
        self.tcp_rcv_list[dest_address] = {
            'EVENT': threading.Event(), 'COUNT': 0, 'MAX': len(port_list)
        }

        #Recorriendo lista de puertos a enviar TCP
        for dest_port in port_list:
            #Campos cabecera TCP
            TCP.Destination_Port = dest_port
            TCP.setSequence()
            
            #Enviando paquete
            self.sock_sender.sendto(IP.to_bytes() + TCP.to_bytes(IP), (dest_address, dest_port))

            #Añadiendo paquetes a la lista de espera
            if num_sended == 1:
                self.tcp_wait_list[dest_address][dest_port] = {
                    'TIME': time(),
                    'SEND': num_sended
                }
            #else: self.tcp_list[dest_address][dest_port]['SEND'] = num_sended

        #Si no se recibieron los tres paquetes antes de que se venciera el timeout
        if not self.tcp_rcv_list[dest_address]['EVENT'].wait(timeout=self.TIME_OUT * num_sended):
            #Obteniendo puertos aun pendientes
            port_list = self.getPendingPorts(dest_address, port_list, TCP = True)

            if len(port_list) == 0: return

            #Retransmitir
            self.sendTCP(IP, TCP, dest_address, port_list, num_sended + 1)        

    def receiveTCP(self, stop_event:threading.Event, Socket, source_address):
        while not stop_event.is_set():
            #Si hay algo que leer          
            if len(select([Socket], [], [], self.TIME_OUT)[0]): #Si hay algo que leer
                data, address = Socket.recvfrom(80) #Cabecera IP + Cabecera TCP
                address = address[0]

                #Si la direccion ip no es la esperada, saltar iteracion
                if address != source_address: continue

                #Obteniendo tiempo de respuesta
                time_rcv = time()

                #Desempaquetando IP
                ip = IP.from_bytes(data)

                #Desempaquetando TCP
                tcp = TCP.from_bytes(ip.Data)
                source_port = tcp.Source_Port

                #Si el puerto no esta en la lista de espera
                if source_port not in self.tcp_wait_list[address]: continue

                #Obteniendo tiempo de envio
                time_rtt = time_rcv - self.tcp_wait_list[address][source_port]['TIME']
                num_sended = self.tcp_wait_list[address][source_port]['SEND']

                #Si tiene los flags esperados
                if (tcp.Flag_SYN and tcp.Flag_ACK) or tcp.Flag_RST:
                    #Notificando la recepcion del paquete
                    self.tcp_rcv_list[address]['COUNT'] += 1 #Aumentando contador de recibidos para esta IP

                    #Si se recibieron todos los paquetes enviados
                    if self.tcp_rcv_list[address]['COUNT'] == self.tcp_rcv_list[address]['MAX']:
                        self.tcp_rcv_list[address]['EVENT'].set() #Activar evento

                    #Eliminando de la lista de espera
                    del self.tcp_wait_list[address][source_port]

                    #Si el puerto esta abierto
                    if tcp.Flag_SYN and tcp.Flag_ACK:
                        #Agregando a lista de puertos como abierto
                        self.tcp_ready_list[address][source_port] = {
                            'TYPE': 'tcp',
                            'STATE': PortStates.open,
                            'SEND': num_sended,
                            'RTT': time_rtt   
                        }

                    #Si el puerto esta cerrado
                    elif tcp.Flag_RST: #Puerto cerrado
                        #Agregando a lista de puertos como cerrado
                        self.tcp_ready_list[address][source_port] = {
                            'TYPE': 'tcp',
                            'STATE': PortStates.closed,
                            'SEND': num_sended,
                            'RTT': time_rtt   
                        }

                
    def detectUDP(self, IP, UDP):
        #Campos cabecera IP
        IP.setID()

        #Variables utiles
        dest_address = IP.Destination_IP.exploded

        #Inicializando entrada de las listas
        self.udp_wait_list[dest_address] = {} #Lista de espera
        self.udp_ready_list[dest_address] = {} #Lista de sondeados

        #Creando socket de recepcion
        SOCKET_RCV = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        SOCKET_RCV.setblocking(False)

        #Lanzando hilo de recepcion
        thread_rcv_finish = threading.Event() #Creando evento para terminar el hilo
        thread_rcv = threading.Thread(
            target=self.receiveUDP, name = "RCV UDP: " + dest_address, args=(
                thread_rcv_finish, SOCKET_RCV, dest_address
            )
        )
        thread_rcv.start()

        #Obteniendo lista de puertos
        range_ports = iter(range(self.MIN_PORT, self.MAX_PORT))

        #Recorriendo lista de puertos
        while True:
            #Eligiendo puertos a sondear
            port_list = self.getPorts(range_ports, self.UDP_SIMULTANEOUS_PORT) #2**16 de 3 en 3.

            #Si no faltan puertos
            if port_list == None: break

            #Enviando UDP a los puertos elegidos.
            self.sendUDP(IP, UDP, port_list, num_sended = 1)

        #Esperando finalizacion del hilo de recepcion
        thread_rcv_finish.set()
        thread_rcv.join()

        #Eliminando host de la lista de espera
        del self.udp_wait_list[dest_address]

        #Cerrando socket de recepcion
        SOCKET_RCV.close()

    def sendUDP(self, IP, UDP, port_list, num_sended):
        #Verificando si se ha llegado al limite de retransmiciones
        if (num_sended > self.MAX_RETRANS): return

        #Variables utiles
        dest_address = IP.Destination_IP.exploded

        #Inicializando contador de paquetes recibidos
        self.udp_rcv_list[dest_address] = {
            'EVENT': threading.Event(), 'COUNT': 0, 'MAX': len(port_list)
        }

        #Recorriendo lista de puertos a enviar UDP
        for dest_port in port_list:
            #Campos cabecera UDP
            UDP.Destination_Port = dest_port
            
            #Enviando paquete
            self.sock_sender.sendto(IP.to_bytes() + UDP.to_bytes(IP), (dest_address, dest_port))

            #Añadiendo paquetes a la lista de espera
            if num_sended == 1:
                self.udp_wait_list[dest_address][dest_port] = {
                    'TIME': time(),
                    'SEND': num_sended
                }
            #else: self.udp_list[dest_address][dest_port]['SEND'] = num_sended

        #Si no se recibieron los tres paquetes antes de que se venciera el timeout
        if not self.udp_rcv_list[dest_address]['EVENT'].wait(timeout=self.TIME_OUT * num_sended):
            #Obteniendo puertos aun pendientes
            port_list = self.getPendingPorts(dest_address, port_list)

            if len(port_list) == 0: return

            #Retransmitir
            self.sendUDP(IP, UDP, port_list, num_sended + 1)

    def receiveUDP(self, stop_event:threading.Event, Socket, source_address):
        while not stop_event.is_set():
            #Si hay algo que leer          
            if len(select([Socket], [], [], self.TIME_OUT)[0]): #Si hay algo que leer
                data, address = Socket.recvfrom(80) #Cabecera IP + Cabecera UDP
                address = address[0]

                #Si la direccion ip no es la esperada, saltar iteracion
                if address != source_address: continue

                #Obteniendo tiempo de respuesta
                time_rcv = time()

                #Desempaquetando IP
                ip = IP.from_bytes(data)

                #Desempaquetando UDP
                udp = UDP.from_bytes(ip.Data)
                source_port = udp.Source_Port

                #Si el puerto no esta en la lista de espera
                if source_port not in self.udp_wait_list[address]: continue

                #Obteniendo tiempo de envio
                time_rtt = time_rcv - self.udp_wait_list[address][source_port]['TIME']
                num_sended = self.udp_wait_list[address][source_port]['SEND']

                #Notificando la recepcion del paquete
                self.udp_rcv_list[address]['COUNT'] += 1 #Aumentando contador de recibidos para esta IP

                #Si se recibieron todos los paquetes enviados
                if self.udp_rcv_list[address]['COUNT'] == self.udp_rcv_list[address]['MAX']:
                    self.udp_rcv_list[address]['EVENT'].set() #Activar evento

                #Eliminando de la lista de espera
                del self.udp_wait_list[address][source_port]

                #Agregando a lista de puertos como filtrado
                self.udp_ready_list[address][udp.Destination_Port] = {
                    'TYPE': 'udp',
                    'STATE': PortStates.open_filtered,
                    'SEND': num_sended,
                    'RTT': time_rtt                    
                }


    def receiveICMP(self, stop_event:threading.Event, type_waited:list, code_waited:list):
        Socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        #Mientras no se notifique la detencion
        while not stop_event.is_set():
            #Esperar por mensajes
            if len(select([Socket], [], [], self.TIME_OUT)[0]):
                #Leer mensajes
                data, address = Socket.recvfrom(80)
                address = address[0]

                #Guardando tiempo de recepcion
                time_rcv = time()

                #Si es una IP que no esta en lista de espera
                if (address not in self.udp_wait_list) and (address not in self.tcp_wait_list) and address != self.GATEWAY:
                    continue

                #Desempaquetando IP e ICMP
                ip = IP.from_bytes(data)
                icmp = ICMP.from_bytes(ip.Data)

                #Si no es del tipo y codigo esperado
                if (icmp.Type not in type_waited) and (icmp.Code not in code_waited):
                    continue

                if icmp.Type == 3:
                    #Desempaquetando paquete original
                    ip_origin = IP.from_bytes(icmp.Data)
                    address = ip_origin.Destination_IP.exploded

                    #Si fue recibido en respuesta a mensaje UDP
                    if ip_origin.Protocol == socket.IPPROTO_UDP:
                        self.rcv_ICMP_UDP(icmp, UDP.from_bytes(ip_origin.Data), address, time_rcv)

                    #Si fue recibido en respuesta a mensaje TCP
                    elif ip_origin.Protocol == socket.IPPROTO_TCP:
                        self.rcv_ICMP_TCP(icmp, TCP.from_bytes(ip_origin.Data), address, time_rcv)

            #Si se notifico la detencion
            if stop_event.is_set(): Socket.close()

    def rcv_ICMP_UDP(self, ICMP, UDP, address, time_rcv):
        #Si la direccion esta en la lista de espera (mas especifico)
        if address not in self.udp_wait_list: return

        #Si el puerto no esta en la lista de espera (mas especifico)
        if UDP.Destination_Port not in self.udp_wait_list[address]:
            return

        #Extrayendo entradas
        time_rtt = time_rcv - self.udp_wait_list[address][UDP.Destination_Port]['TIME']
        num_sended = self.udp_wait_list[address][UDP.Destination_Port]['SEND']

        #Notificando la recepcion del paquete
        self.udp_rcv_list[address]['COUNT'] += 1 #Aumentando contador de recibidos para esta IP

        #Si se recibieron todos los paquetes enviados
        if self.udp_rcv_list[address]['COUNT'] == self.udp_rcv_list[address]['MAX']:
            self.udp_rcv_list[address]['EVENT'].set() #Activar evento
        
        #Eliminando de la lista de espera
        del self.udp_wait_list[address][UDP.Destination_Port]

        if ICMP.Type == 3 and ICMP.Code == 3: #Puerto no alcanzable
            #Agregando a lista de puertos como cerrado
            self.udp_ready_list[address][UDP.Destination_Port] = {
                'TYPE': 'udp',
                'STATE': PortStates.closed,
                'SEND': num_sended,
                'RTT': time_rtt                    
            }

        else: #Tipo: 3, Codigo: [1, 2, 9, 10, 13]
            #Agregando a lista de puertos como filtrado
            self.udp_ready_list[address][UDP.Destination_Port] = {
                'TYPE': 'udp',
                'STATE': PortStates.filtered,
                'SEND': num_sended,
                'RTT': time_rtt                    
            }
            
    def rcv_ICMP_TCP(self, ICMP, TCP, address, time_rcv):
        #Si la direccion esta en la lista de espera (mas especifico)
        if address not in self.tcp_wait_list: return

        #Si el puerto no esta en la lista de espera (mas especifico)
        if TCP.Destination_Port not in self.tcp_wait_list[address]: return

        #Extrayendo entradas
        time_rtt = time_rcv - self.tcp_wait_list[address][TCP.Destination_Port]['TIME']
        num_sended = self.tcp_wait_list[address][TCP.Destination_Port]['SEND']

        #Notificando la recepcion del paquete
        self.tcp_rcv_list[address]['COUNT'] += 1 #Aumentando contador de recibidos para esta IP

        #Si se recibieron todos los paquetes enviados
        if self.tcp_rcv_list[address]['COUNT'] == self.tcp_rcv_list[address]['MAX']:
            self.tcp_rcv_list[address]['EVENT'].set() #Activar evento

        #Eliminando de la lista de espera
        del self.tcp_wait_list[address][TCP.Destination_Port]

        #Agregando a lista de puertos como filtrado
        self.tcp_ready_list[address][TCP.Destination_Port] = {
            'TYPE': 'tcp',
            'STATE': PortStates.filtered,
            'SEND': num_sended,
            'RTT': time_rtt   
        }


    def getPorts(self, range_port, num_ports):
            ports = []
            try:
                while num_ports:
                    ports += [next(range_port)]
                    num_ports -= 1
            except StopIteration:
                if len(ports) == 0:
                    return None

            return ports

    def getPendingPorts(self, dest_address, port_list, TCP = False):
        #Revisando que paquetes fueron recibidos
        for i in range(0, len(port_list)):
            port = port_list.pop() #Sacando de los puertos pendientes

            #Si todavia esta en la lista de espera
            if TCP:
                packet_list = self.tcp_wait_list[dest_address]
            else:
                packet_list = self.udp_wait_list[dest_address]

            if port in packet_list:
                port_list.insert(0, port) #Añadiendo a los puertos pendientes
        
        return port_list


class PortStates(object):
    open = 1
    closed = 2
    filtered = 3
    open_filtered = 4

    @staticmethod
    def to_str(state:int):
        if state == PortStates.open: return 'Abierto'
        elif state == PortStates.closed: return 'Cerrado'
        elif state == PortStates.filtered: return 'Filtrado'
        else: return 'Abierto | Filtrado'