#Importando protocolos
from Protocols.IP import IP
from Protocols.ICMP import ICMP
from Protocols.TCP import TCP
from Protocols.UDP import UDP

from Misc.ThreadPool import ThreadPool

import socket, threading
from time import time, sleep
from select import select

from threading import Semaphore, Lock
from ipaddress import IPv4Address

import random, copy

class PortDetection(object):
    def __init__(self, SENDER, TIME_OUT):
        self.SENDER = SENDER
        self.TIME_OUT = TIME_OUT

        self.tcp_wait_list = dict()
        self.tcp_ready_list = dict()
        self.tcp_rcv_list = dict()

        self.udp_wait_list = dict()
        self.udp_ready_list = dict()
        self.udp_rcv_list = dict()

        #Retransmiciones maximas
        self.MAX_RETRANS = 1

        #Cantidad de puertos a sondear simultaneamente
        self.TCP_SIMULTANEOUS_PORT = 50
        self.UDP_SIMULTANEOUS_PORT = 3
        #self.COUNT_SEND_PORT = 3

        #Rango de puertos a sondear
        self.MIN_PORT = 0
        self.MAX_PORT = 1025

        #CREANDO HILO DE RECEPCION ICMP
        self.rcv_ICMP_event = threading.Event() #Creando evento para terminar el hilo
        self.rcv_ICMP_thread = threading.Thread(
            target=self.receiveICMP, name = "Receive ICMP...", kwargs={
                'type_waited': [3],
                'code_waited': [1, 2, 3, 9, 10, 13]
            }
        )
        self.rcv_ICMP_thread.start()

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
            self.SENDER.sendto(IP.to_bytes() + TCP.to_bytes(IP), (dest_address, dest_port))

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
            self.SENDER.sendto(IP.to_bytes() + UDP.to_bytes(IP), (dest_address, dest_port))

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


    def receiveICMP(self, type_waited:list, code_waited:list):
        Socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        stop_event = self.rcv_ICMP_event

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
                if (address not in self.udp_wait_list) and (address not in self.tcp_wait_list):
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

                    #Si fue recibido en respuesta a mensaje UDP
                    if ip_origin.Protocol == socket.IPPROTO_UDP:
                        self.rcv_ICMP_UDP(icmp, UDP.from_bytes(ip_origin.Data), address, time_rcv)

                    #Si fue recibido en respuesta a mensaje TCP
                    elif ip_origin.Protocol == socket.IPPROTO_TCP:
                        self.rcv_ICMP_TCP(icmp, TCP.from_bytes(ip_origin.Data), address, time_rcv)

            #Si se notifico la detencion
            if stop_event.is_set(): Socket.close()

    def rcv_ICMP_UDP(self, ICMP, UDP, address, time_rcv):
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

