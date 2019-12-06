__version__ = "1.0"

#Importando libreria de parametros
from Misc.docopt import docopt

#Importando core de nmap
from ncore import HostDetecter, PortDetecter, PortStates, Protocols

#Importando modulos propios
from Misc.Tools import Tools

#Importando modulos generales
import socket
from ipaddress import IPv4Address, IPv4Network

#Manejando parametros de la linea de comando
uso = """
Usage: nmap [-m <max_host>] [-t <timeout>] [-d <parallel_discovery>] [-p <parallel_host>] [-r <range_port>] [-c <max_try>] [-w <timeout>] <destino>
       nmap --help
       nmap --version

Arguments:
   destino                      IP o nombre del host de destino IP de red de destino

Options:   
  -m <max_host>                 Numero maximo de host que se intentaran encontrar durante la fase de descubrimiento de objetivos.
                                [default: -1]
  -t <timeout>                  Tiempo maximo en segundos durante el cual se esperara la respuesta de un host durante la fase de descubrimiento de objetivos.
                                [default: 3]
  -d <parallel_discovery>       Numero de direcciones IP que se utilizaran simultaneamente durante la fase de descubrimiento de objetivos.
                                [default: 25]

  -p <parallel_host>            Numero de host que se sondearan simultaneamente durante la fase de sondeo de puertos.
                                [default: 5]    
  -r <range_port>               Rango de puertos que seran sondeados durante la fase de sondeo de puertos.
                                [default: 1025]
  -w <timeout>                  Tiempo maximo en segundos durante el cual se esperara la respuesta de un puerto destino durante la fase de sondeo de puertos.
                                [default: 1]
  -c <max_retrans>              Numero de intentos maximos para alcanzar un host o puerto destino durante cualquier fase.
                                [default: 3]                                                                             
  -h, --help                    Muestra esta información de ayuda.
  -v, --version                 Muestra la version del programa.
"""

#Almacenando los parametros pasados mediante la linea de comandos.
args = docopt(uso, version = __version__)

#Extrayendo los parametros
IP_DESTINO = args['<destino>']

#Parametros de la fase de descubrimiento
SIMULTANEOUS_DISCOVERY = int(args['-d']) #25
MAX_HOST_DETECTED = int(args['-m']) #-1
HOST_TIMEOUT = int(args['-t']) #3 seg

#Parametros de la fase de sondeo de puertos
SIMULTANEOUS_HOST = int(args['-p']) #5
PORT_TIMEOUT = int(args['-w']) #1
RANGE_PORT = int(args['-r'])

#Parametros de ambas fases
MAX_RETRANS = int(args['-c']) # 3 intentos


MAX_HOST_DETECTED = int(args['-m']) #-1
#Range port


#Estableciendo la red o host que se utilizara
try:
    NETWORK = IPv4Network(IP_DESTINO, False) # Red a analizar
    #if NETWORK.netmask.exploded == '255.255.255.255':
    #    pass
except:
    print("\nERROR: La direccion de red o host proporcionada no es valida.\n")
    exit(-1)

#OBTENIENDO DIRECCION IP DEL ANFITRION
try:
    MY_IP, GATEWAY_IP, GATEWAY_IF = Tools.get_MyIP(NETWORK) # Datos de red propios
except:
    print("\nERROR: No se encontro ninguna interfaz de red disponible.\n")
    exit(-1)

#Informando variables
print("\n..::-= INFORMACION DEL ANFITRION =-::..\n")
print("IP: %s\tGATEWAY: %s\tIF: %s" % (MY_IP, GATEWAY_IP, GATEWAY_IF))

####################################################################
print("\n..::-= DESCUBRIMIENTO DE HOST OBJETIVOS =-::..\n", )
####################################################################

#Realizando deteccion de hosts
detecter = HostDetecter(
    Protocols(MY_IP, GATEWAY_IP),
    MAX_RETRANS, HOST_TIMEOUT, SIMULTANEOUS_DISCOVERY, MAX_HOST_DETECTED
)
result = detecter.find(NETWORK)

#Lista ordenada de host vivos
alive_list = []

#Imprimiendo informe de host vivos
for host in NETWORK.hosts():
    host = host.exploded

    if (host not in result['ICMP']) and (host not in result['TCP']):
        continue

    if host in result['ICMP']:
        icmp_ping = Tools.get_time(result['ICMP'][host]['RTT'])
        icmp_count = result['ICMP'][host]['SEND']
    else: icmp_ping = '???'; icmp_count = 0

    if host in result['TCP']:
        tcp_ping = Tools.get_time(result['TCP'][host]['RTT'])
        tcp_count = result['TCP'][host]['SEND']
    else: tcp_ping = '???'; tcp_count = 0

    try:
        #Obteniendo el nombre asociado a la IP del host.
        IP_name = socket.gethostbyaddr(host)[0]
    except socket.herror:
        #Si la IP no tiene asociada ningun nombre, entonces guardamos "-"
        IP_name = '-'

    print("> {:40s} ICMP PING ({}): {:15} TCP SYN ({}): {}".format(
        host + ' (' + IP_name + ')',
        icmp_count,
        icmp_ping,
        tcp_count,
        tcp_ping
    ))

    #Agregando a la lista ordenada de host vivos
    alive_list += [(host, IP_name)]

print("\nDuracion total:", Tools.get_time(result['TIME']))

####################################################################
print("\n\n..::-= SONDEO DE PUERTOS EN HOST VIVOS =-::..")
####################################################################

#Realizando sondeo de puertos
detecter = PortDetecter(
    Protocols(MY_IP, GATEWAY_IP), GATEWAY_IP, MAX_RETRANS, PORT_TIMEOUT, SIMULTANEOUS_HOST, 0, RANGE_PORT
)
result = detecter.probe(alive_list)

#Mostrando informe
for address in alive_list:
    host_name = address[1]
    address = address[0]

    #Contadores
    port_open = 0; port_close = 0; port_filter = 0; port_open_filter = 0

    print("\n>>>", address, "(" + host_name + ")")

    if (address not in result['TCP']) and (address not in result['UDP']):
        print("\t > No se recibio respuesta de ningun puerto.")
        continue

    for num_port in range(0, RANGE_PORT):
        port_tcp = None; port_udp = None

        #Extrayendo informacion de los puertos por cada protocolo
        if num_port in result['TCP'][address]: port_tcp = result['TCP'][address][num_port]
        if num_port in result['UDP'][address]: port_udp = result['UDP'][address][num_port]

        #Procesando estados de los puertos
        if port_tcp != None and port_udp != None:
            #Si el puerto esta abierto en TCP o UDP
            if port_tcp['STATE'] == PortStates.open: port = port_tcp
            elif port_udp['STATE'] == PortStates.open: port = port_udp

            #Si el puerto esta cerrado tanto con TCP y UDP
            elif port_tcp['STATE'] == PortStates.closed and port_udp['STATE'] == PortStates.closed:
                port = port_tcp

            #Si el puerto esta filtrado tanto en TCP como UDP
            elif port_tcp['STATE'] == PortStates.filtered and port_udp['STATE'] == PortStates.filtered:
                port = port_tcp

            #Si TCP esta cerrado y UDP esta Abierto | Filtrado
            elif port_tcp['STATE'] == PortStates.closed and port_udp['STATE'] == PortStates.open_filtered:
                port = port_udp

            #Si TCP esta filtrado y UDP esta Abierto | Filtrado
            elif port_tcp['STATE'] == PortStates.filtered and port_udp['STATE'] == PortStates.open_filtered:
                port = port_tcp
            
            #Si no filtrado
            else:
                port = port_tcp
                port['STATE'] = PortStates.filtered

        elif port_tcp != None: port = port_tcp
        elif port_udp != None: port = port_udp
        else: continue

        #Si el puerto esta abierto
        if port['STATE'] == PortStates.open:
            port_open += 1

        #Si esta abierto | filtrado
        elif port['STATE'] == PortStates.open_filtered:
            port_open_filter += 1

        #Si el puerto esta filtrado
        elif port['STATE'] == PortStates.filtered:
            port_filter += 1
            port['TYPE'] = '?'
            #continue

        #Si el puerto esta cerrado
        elif port['STATE'] == PortStates.closed:
            port_close += 1
            port['TYPE'] = '?'
            continue
        
        #Obteniendo datos de protocolos
        protocol = Tools.getProtocol(num_port, port['TYPE'])

        print("\t > {:21} {:10} {:25} Estado: {:25} Sondeos: {:5s} RTT: {}".format(
            str(num_port) + '/' + str(port['TYPE']), protocol[0], protocol[1], PortStates.to_str(port['STATE']), str(port['SEND']), Tools.get_time(port['RTT'])
        ))
        
    if port_open: print("\n\tPuertos abiertos:", port_open)
    if port_open_filter: print("\tPuertos abiertos | filtrados:", port_open_filter)
    if port_filter: print("\tPuertos filtrados:", port_filter)
    if port_close: print("\tPuertos cerrados:", port_close)

print("\nDuracion total:", Tools.get_time(result['TIME']))