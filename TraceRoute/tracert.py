__version__ = "1.0"

#Importando modulos generales
import socket, struct, time

#Importando modulo de gestion de parametros de la linea de comandos.
from docopt import docopt

#Importando clases encargadas de desempaquetar los paquetes de cada protocolo
from Protocols.IP import IP as IPPacket
from Protocols.ICMP import ICMP as ICMPPacket
from Protocols.UDP import UDP as UDPPacket

#Manejando parametros de la linea de comando
uso = """
Usage: tracert [-a] [-p <puerto>] [-s <saltos>] <destino>
       tracert --help
       tracert --version

Arguments:
   destino                       IP de destino o nombre del host de destino

Options:
  -a                            Modo avanzado o detallado.
                                [default: False]
  -p <puerto>                   Puerto al que se enviaran los paquetes UDP.
                                [default: 33434]
  -s <saltos>                   Numero maximo de saltos permitidos.
                                [default: 30]
  -h, --help                    Muestra esta información de ayuda.
  -v, --version                 Muestra la version del programa.
"""

#Almacenando los parametros pasados mediante la linea de comandos.
args = docopt(uso, version = __version__)

#Extrayendo parametros
HOST = args['<destino>'] #IP Destino ó host de destino
PORT = int(args['-p']) #Puerto destino
MAX_HOPS = int(args['-s']) #N° Saltos maximos permitidos
ADVANCED_MODE = args["-a"] #Activacion del modo detallado

#Obteniendo una direccion IP si el host de destino fue especificado
#mediante un nombre (Ej: www.google.com)
IP_ADDRESS = (socket.gethostbyname(HOST), int(PORT))

#Creando RAW socket, donde:
#   socket.AF_INET => Indica que el socket trabajara con direcciones IPv4
#   socket.SOCK_RAW => Indica que el socket sera de tipo raw y por lo tanto,
#                      puede ser utilizado con cualquier protocolo.
#   socket.IPPROTO_ICMP => Indica que el socket gestionara el protocolo ICMP.
raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

#Estableciendo el tiempo que se debe esperar para recibir
#un paquete, mediante la siguiente estructura:
#
#   struct timeval{
#       long segundos;
#       long milisegundos;
#   }
#
# Donde:
#   socket.SOL_SOCKET => hace referencia a la configuracion del socket
#   socket.SO_RCVTIMEO => hace referencia al tiempo que se espera por un paquete
#   struct.pack("ll", 5, 0) => Una estructura de tipo timeval, especificada anteriormente

raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 5, 0)) # TimeOut = 5 Seg

#Vinculando raw socket a la interfaz activa en el puerto especificado
#por la variable "PORT".
raw.bind(('', PORT))

#Creando socket UDP, donde:
#   socket.SOCK_DGRAM => Indica que el socket sera de tipo datagrama, y por lo tanto
#                        no estara orientado a conexion.
#   socket.IPPROTO_UDP => Indica que el socket trabajara con el protocolo UDP.
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

#Imprimiendo los datos pasados por la linea de comandos, para informar el inicio del programa.
print("Trazando ruta hacia {} ({}) al puerto {} con {} saltos maximos\n".format(
    HOST, IP_ADDRESS[0], PORT, MAX_HOPS
))

#Variables de control
IP_RECEIVE = (0,0) #Variable en donde se almacenara la IP desde donde se envio
                   #el ultimo paquete ICMP.
ACT_TTL = 0 #Variable que almacenara el TTL con el que se estara trabajando en cada salto.

while IP_ADDRESS[0] != IP_RECEIVE[0]:
    #Inicializando listas
    timer = list() #Lista que almacena los tiempos de envio y recepcion de cada paquete UDP.
    packets = list() #Lista que almacena los paquetes IP recibidos en esta vuelta del ciclo.
    packets_icmp = list() #Lista que almacena los paquetes IP que estan contenidos en
                          #los paquetes IP de la lista anterior.
    packets_udp = list() #Lista que almacena los datagramas UDP originales.

    #Aumentando el valor de ACT_TTL, para establecer el TTL actual.
    ACT_TTL += 1

    #Imprimiendo el valor del TTL que se utilizara en este salto.
    print(">  TTL =", ACT_TTL, "\t", end='')

    #Especificando el TTL que utilizara el socket UDP al enviar los datagramas.
    udp.setsockopt(socket.SOL_IP, socket.IP_TTL, ACT_TTL)
    
    #Iniciando un ciclo que se repetira 3 veces, una por cada datagrama UDP que se debe enviar.
    for i in range(0, 3):
        #Guardando en la lista el tiempo en que se envia el datagrama UDP.
        timer.append(time.time())

        #Enviando datagrama UDP a la direccion especificada por "IP_ADDRESS".
        udp.sendto("Tracert".encode(), IP_ADDRESS)

        try:
            #Recibiendo mensaje ICMP de error, con una longitud maxima de 1480 bytes.
            #El 1480 se debe a que ese es el tamaño maximo permitido de datos que pueden
            #estar contenidos en una trama ethernet.
            #Y la funcion recvfrom descarta ethernet y nos entrega un paquete IP completo, es decir
            #los datos contenidos en ethernet.
            DATA, IP_RECEIVE = raw.recvfrom(1480)
        except BlockingIOError:
            #Si el tiempo de espera se agoto, en vez de almacenar el RTT se guarda "???".
            timer[i] = "???"
            #Y Continuamos a la proxima vuelta del ciclo for, para enviar el proximo datagrama.
            continue
        else:
            #Si recibimos respuesta antes de que el tiempo de espera se agote,
            #calculamos el RTT (Tiempo de ida y vuelta).
            #   (Tiempo de Recepcion - Tiempo de Envio) * 100   => Para obtener el RTT en milisegundos.
            timer[i] = round((time.time() - timer[i]) * 1000, 2)

            #Y guardamos los bytes (Paquetes IP) recibidos en la lista.
            packets.append(DATA)

    #Imprimiendo informe.
    if (len(packets) == 0): #Si no recibimos ni un solo ICMP de error, entonces imprimimos "* * *".
        print("*   *   *\n")
    else:
        try:
            #Obteniendo el nombre asociado a la IP desde la que nos enviaron el paquete ICMP.
            IP_RECEIVE_NAME = socket.gethostbyaddr(IP_RECEIVE[0])[0]
        except socket.herror:
            #Si la IP no tiene asociada ningun nombre, entonces guardamos "-"
            IP_RECEIVE_NAME = '-'

        #Imprimiendo la IP y el nombre (si lo tiene) del que envio el ICMP, mas el RTT de cada respuesta.
        print("{} ({})\t\t{}\n".format(
            IP_RECEIVE[0], IP_RECEIVE_NAME, [str(n) + " ms" for n in timer]
        ))

    #Imprimiendo informe avanzado
    if (ADVANCED_MODE == True and len(packets) > 0):
        print("    Paquetes de respuesta (IP):")
        #Recorriendo la lista que contiene cada paquete IP recibido anteriormente.
        for packet in packets:
            ip = IPPacket(packet) #Obteniendo un objeto de la clase IP, que se encarga de
                                  #separar cada campo del paquete IP.

            #Imprimiendo campos mas relevantes del paquete IP actual.
            print("    {} | ( {} => {} )\tVersion = {} , ID = {} , Longitud datagrama = {} , DF = {} , MF = {} , TTL = {}".format(
                    packets.index(packet) + 1,
                    ip.getSourceAddress(),
                    ip.getDestinationAddress(),
                    ip.version,
                    ip.identificador,
                    ip.longitud_trama,
                    ip.DontFragment,
                    ip.MoreFragment,
                    ip.TTL
                ))

            #Guardando en la lista, el paquete ICMP contenido dentro de este paquete IP.
            packets_icmp.append(ip.Data)

        ###
        print("\n    Paquetes de respuesta (IP => ICMP):")
        packets.clear()
        #Recorriendo la lista de paquetes ICMP que estaban contenidos en los paquetes IP recibidos.
        for packet in packets_icmp:
            icmp = ICMPPacket(packet) #Obteniendo un objeto de la clase ICMP, que se encarga de
                                      #separar cada campo del paquete ICMP.

            #Imprimiendo campos mas relevantes del paquete ICMP.
            print("    {} | Tipo = {} , Codigo = {}".format(
                packets_icmp.index(packet) + 1,
                icmp.Type,
                icmp.Code
            ))
            
            #Guardando en una lista los fragmentos de los paquetes IP originales.
            packets.append(icmp.Data)

        ###
        print("\n     Paquetes de respuesta (IP => ICMP => IP):")
        #Recorriendo la lista de los paquetes IP originales, que contenian los datagramas UDP
        #que se enviaron anteriormente.
        for packet in packets:
            ip = IPPacket(packet) #Obteniendo un objeto de la clase IP, que se encarga de
                                  #separar cada campo del paquete IP.

             #Imprimiendo campos mas relevantes del paquete IP actual.
            print("    {} | ( {} => {} )\tVersion = {} , ID = {} , Longitud datagrama = {} , DF = {} , MF = {} , TTL = {}".format(
                    packets.index(packet) + 1,
                    ip.getSourceAddress(),
                    ip.getDestinationAddress(),
                    ip.version,
                    ip.identificador,
                    ip.longitud_trama,
                    ip.DontFragment,
                    ip.MoreFragment,
                    ip.TTL
                ))

            packets_udp.append(ip.Data)

        ###
        print("\n     Paquetes de respuesta (IP => ICMP => IP => UDP):")
        #Recorriendo la lista de los datagramas UDP originales, que contenian los paquetes IP originales.
        for packet in packets_udp:
            udp_datagram = UDPPacket(packet) #Obteniendo un objeto de la clase UDP, que se encarga de
                                  #separar cada campo del datagrama UDP.

             #Imprimiendo campos mas relevantes del paquete IP actual.
            print("    {} | ( PO: {} => PD: {} )\tLongitud = {} , Datos = {}".format(
                    packets_udp.index(packet) + 1,
                    udp_datagram.SourcePort,
                    udp_datagram.DestinationPort,
                    udp_datagram.Lenght,
                    str(udp_datagram.Data)[1:]
                ))

        print("\n\n")

    #Comprobando que todavia no hayamos llegado al destino
    if len(packets_icmp) > 0:
        icmp = ICMPPacket(packets_icmp[0])
        if (icmp.Code == 3 and icmp.Type == 3):
            break

    #Comprobando que no se hayan sobrepasado los saltos maximos.
    if ACT_TTL >= MAX_HOPS and IP_ADDRESS[0] != IP_RECEIVE[0]:
        print("Saltos maximos alcanzados... Operacion cancelada...")
        break

#Cerrando sockets
udp.close()
raw.close()