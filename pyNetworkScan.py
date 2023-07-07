import xmltodict
import pprint
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP
from collections import OrderedDict
import pygraphviz as pgv
import socket
import numpy as np
from multiprocessing.pool import Pool
import multiprocessing
from tqdm import tqdm
from functools import partial

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

def get_xml_scanned_hosts(scan_dict, net=""):
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
def tracert(host):
    ans, unans = sr(IP(dst=host, ttl=(1,6))/ICMP(), timeout=2, verbose=0, retry=2)
    hops=[]
    ans.summary( lambda s, r : hops.append(str(r.sprintf("%IP.src%"))))
    hops = list(dict.fromkeys(hops))
    hops.insert(0, thisip)
    hops.insert(-1, host[:host.rfind(".")]+ ".0")
    return (host,hops)
        
 

def perform_traceroute(scanned_hosts):
   
    with multiprocessing.Pool(processes=4) as p:
        with tqdm(total=len(scanned_hosts), unit="Traces") as trace_pbar:
            for x in p.imap_unordered(tracert, scanned_hosts.keys()):
                # print(f'{x[0]} {x[1]}')

                scanned_hosts[str(x[0])]["parentIP"] = x[1]
                trace_pbar.update()
            


        
    
        

def get_random_hex_color():
    color = list(np.random.choice(range(40,225),size=3))
    return '#{:02x}{:02x}{:02x}'.format(color[0], color[1], color[2])
    
def gen_ip_list(ip_range_str="192.168.0-15.1-150"):
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
    resp = sr1(icmp, timeout=.5, verbose=0)
    
    if resp == None:
        return (ip, False)
    else:
        #print(f"{ip} is UP")
        return (ip, True)

def get_live_hosts(ipList): #zero
    ips = set()
    with multiprocessing.Pool(processes=100) as p:
        with tqdm(total=len(ipList), unit="Hosts") as pbar:
            for x in p.imap_unordered(is_up, ipList):
                if x[1] == True:
                    pbar.set_description(f"Found {len(ips)} hosts.")
                    ips.add(x[0])
                pbar.update()
    p.close()
    p.join()
    return list(ips)

def check_port(hostandport):

    packet = IP(dst=str(hostandport[0]))/TCP(dport=int(hostandport[1]))
    
    resp = sr1(packet, verbose=0, timeout=.5)
    if resp is not None and resp.haslayer(TCP) and resp.getlayer(TCP).flags==0x12:
        return (hostandport[0], hostandport[1], True)
    else:
        return (hostandport[0], hostandport[1], False)

def get_scan_hosts_ports(liveHostList, top_ports=1000): 
    scanned_hosts = {}
    
    for lh in liveHostList:
        scanned_hosts[str(lh)] = {"theports": {}, "parentIP": []}

    ports = load_ports_file("theports.txt", top_ports)
    # pprint.pprint(ports)
    hostports = []
    for h in liveHostList:
        for p in ports.keys():
            hostports.append((h,p))
    
    openPorts = {}
    with multiprocessing.Pool(processes=100) as p:
        with tqdm(total=len(hostports), unit="Ports", leave=True, position=0) as host_pbar:
            host_pbar.set_description("Ports scan: ")
            for x in p.imap_unordered(check_port, hostports):
                if x[2]==True:

                    scanned_hosts[f'{x[0]}']["theports"][str(x[1])]=ports[f'{x[1]}']

                host_pbar.update()
    
    p.close()
    p.join()


    return scanned_hosts
    
        
    


def load_ports_file(infile="theports.txt", top_ports=1000): #1st
    ports = dict()
    with open(infile, "r") as line:
        for l in line.readlines()[0:top_ports]:
            theline = l.strip().split(",")
            ports[theline[1]] = theline[0]
    return ports


if __name__ == '__main__':
    scanned_hosts = dict()
    
    
    scan_dict = read_xml('outputscan.xml')
    thisip= getMyIP()
    ##scanned_hosts = get_xml_scanned_hosts(scan_dict)
    liveHosts = get_live_hosts(gen_ip_list("192.168.0-50.100-150"))
    scanned_hosts = get_scan_hosts_ports(liveHosts, 200)
    
    uniqueNets = set([ips[:ips.rfind(".")] for ips in scanned_hosts])
    perform_traceroute(scanned_hosts)
    for un in uniqueNets:
        #print (un)
        create_network_graph({k:v for (k,v) in scanned_hosts.items() if un in k},un)
    # 192.168.0-50.2-150
    

    create_network_graph(scanned_hosts)
    
