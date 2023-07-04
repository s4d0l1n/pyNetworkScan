import xmltodict
import pprint
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from collections import OrderedDict
import pygraphviz as pgv
import socket
import numpy as np


thisip=""
allhops = []
hostsAndHops = dict()
def read_xml(file_name):
    with open(file_name) as file:
        return xmltodict.parse(file.read())

def getMyIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    myip = s.getsockname()[0]
    s.close()
    return myip

def get_scanned_hosts(scan_dict, net=""):
    scanned_hosts = {}

    for host in scan_dict['nmaprun']['host']:
        address = host['address']['@addr'] if type(host['address']) is not list else host['address'][0]['@addr']
        ports = host['ports']['port'] if "port" in host['ports'] else []

        open_ports = get_open_ports(ports)

        scanned_hosts[address] = {"theports": open_ports, "parentIP": None}

    return scanned_hosts


def get_open_ports(ports):
    open_ports = {}

    if isinstance(ports, list):
        for port in ports:
            open_ports[port.get('@portid')] = port.get('service').get('@name')
    else:
        open_ports[ports['@portid']] = ports['service']['@name']

    return open_ports


def perform_traceroute(scanned_hosts):
    for host in scanned_hosts.keys():
        print(f"tracerouting {host}:")
        ans, unans = sr(IP(dst=host, ttl=(1,6))/ICMP(), timeout=2, verbose=0, retry=2)
        hops=[]
        ans.summary( lambda s, r : hops.append(str(r.sprintf("%IP.src%"))))
        hops = list(dict.fromkeys(hops))
        hops.insert(0, thisip)
        hops.insert(-1, host[:host.rfind(".")]+ ".0")
        
        scanned_hosts[host]["parentIP"] = hops
        hostsAndHops[host] = hops
        pprint.pprint(scanned_hosts[host])
    pprint.pprint(hostsAndHops)
        

def get_random_hex_color():
    color = list(np.random.choice(range(40,225),size=3))
    return '#{:02x}{:02x}{:02x}'.format(color[0], color[1], color[2])
    
def gen_ip_list(ip_range_str):
    ip_list = []

    octets = ip_range_str.split(".")
    for o in octets:
        if "," in o:
            comma_separated_ranges = o.split(",")
            values = []
            for r in comma_separated_ranges:
                if "-" in r:
                    start, end = map(int, r.split("-"))
                    values.extend(list(range(start, end + 1)))
                else:
                    values.append(int(r))
            ip_list.append(values)
        elif "-" in o:
            start, end = map(int, o.split("-"))
            ip_list.append(list(range(start, end + 1)))
        else:
            ip_list.append([int(o)])

    return ['.'.join(map(str, ip)) for ip in itertools.product(*ip_list)]



def create_network_graph(scanned_hosts, filename="all"):
    graph = pgv.AGraph(overlap=False, splines="ortho", directed=True, rankdir="TB", strict=False)
   

    for host, data in scanned_hosts.items():
        parent_node = data["parentIP"]
        maxHops = len(data["parentIP"])

        formatedPorts = {'<BR />' +  str(key) + ':' + str(value) for key, value in data['theports'].items()} 
        # 

        nlist = parent_node
        path_color = get_random_hex_color()
        for level, value in enumerate(parent_node):
            graph.add_node(value, label=f"IP: {value}", shape='rectangle', row=level)
        
        graph.add_node(host, label=f"<IP: {host} \n Ports: \n {formatedPorts}>", shape='rectangle', color=f"{path_color}", row=len(parent_node)-1)    
        #graph.add_path(list(parent_node))
        if len(nlist) > 1:
            fromv = nlist.pop(0)
            
            while len(nlist) > 0:
                tov = nlist.pop(0)
                # lastHop[:lastHop.rfind(".")]
                
                if len(graph.in_edges((fromv,tov))) < 7:
                    if graph.has_edge(fromv,tov, key=f"{fromv}_{tov}") == False:
                        
                        graph.add_edge(fromv, tov, key=f"{fromv}_{tov}_{host}", color=f"{path_color}")
                else:
                    if graph.has_edge(fromv, tov):
                        graph.remove_edges_from(graph.in_edges(tov))
                        graph.add_edge(fromv, tov, key=f"{fromv}_{tov}", penwidth="4", color="blue")

                fromv = tov
    graph.layout("dot")
    graph.draw(f"graph_{filename}.svg")

def is_up(ip):
    icmp = IP(dst=ip)/ICMP()
    resp = sr1(icmp, timeout=1)
    if resp == None:
        return False
    else:
        return True
#  def gen_IP_list(ipExpression = "0.0.0.0"):
     

if __name__ == '__main__':
    scan_dict = read_xml('outputscan.xml')
    thisip= getMyIP()
    scanned_hosts = get_scanned_hosts(scan_dict)
    uniqueNets = set([ips[:ips.rfind(".")] for ips in scanned_hosts])
    perform_traceroute(scanned_hosts)
    # for un in uniqueNets:
    #     #print (un)
    #     create_network_graph({k:v for (k,v) in scanned_hosts.items() if un in k},un)
    


    

    
    create_network_graph(scanned_hosts)
    #pprint.pprint(allhops)
