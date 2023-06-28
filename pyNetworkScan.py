import xmltodict
import pprint
from scapy.layers.inet import traceroute
from collections import OrderedDict
import pygraphviz as pgv
import socket

thisip=""
allhops = []
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

        scanned_hosts[address] = {"theports": open_ports, "parentIP": [thisip]}

    return scanned_hosts


def get_open_ports(ports):
    open_ports = {}

    if isinstance(ports, list):
        for port in ports:
            open_ports[port.get('@portid')] = port.get('service').get('@name')
    else:
        open_ports[ports['@portid']] = ports['service']['@name']

    return open_ports.items()
def printPacket():
    print("fuck")

def perform_traceroute(scanned_hosts):
    for host in scanned_hosts.keys():
        result, unans = traceroute(host, maxttl=6, verbose=True)
        
        hops=[]
        
       
        
        


        
        #print(myresult)

        
        for trace in result.get_trace().values():
            addit = True    
            
            for sub_trace in trace.values():
                    
                r = list(sub_trace)
                #s, t = zip(*r)
                hops.append(str(r[0]))
                print(f"the hops: {hops}")

                if str(r[1]) == "True":
                    lastHop = hops[-1]
                    lastHop = lastHop[:lastHop.rfind(".")] + ".1"
                    print(f"last hop is: {lastHop}")
                    if len(hops) > 1 : hops.insert(-1, lastHop)
                    hops.insert(0, thisip)
                    
                    for g,h in result:
                        if h.sprintf("%TCP.flags%") == "SA":
                            addit = False
                    if addit:
                        scanned_hosts[host]["parentIP"] = list(dict.fromkeys(hops))
                        allhops.append(list(dict.fromkeys(hops)))
                    print(scanned_hosts[host]["parentIP"])
                    print(f"added path: {hops}")


        # prevhop = [
        #     keyb
        #     for trace in result.get_trace().values()
        #     for sub_trace in trace.values()
        #     for keyb in sub_trace if type(keyb) != bool
        #     ]
        # #pprint.pprint(prevhop)
        # scanned_hosts[host]["parentIP"] = prevhop

        
    

def create_network_graph(scanned_hosts, filename="all"):
    graph = pgv.AGraph(overlap=False, splines="curved", directed=True, rankdir="LR")

    for host, data in scanned_hosts.items():
        parent_node = list(data["parentIP"])


        formatedPorts = { "<BR />" +p + ": " + v for p,v in data['theports']} 
        graph.add_node(host, label=f"<IP: {host} \n Ports: {formatedPorts}>", shape='rectangle')
        graph.add_path(parent_node)
        #graph.add_edges_from(edges, color="red", dir="forward", arrowType="normal")
        nlist = parent_node
        if len(nlist) > 0:
            fromv = nlist.pop(0)
            while len(nlist) > 0:
                tov = nlist.pop(0)
                graph.add_edge(fromv, tov, penwidth=5)
                fromv = tov
        


    graph.layout("neato")
    graph.draw(f"graph_{filename}.svg")


if __name__ == '__main__':
    scan_dict = read_xml('outputscan.xml')
    thisip= getMyIP()
    scanned_hosts = get_scanned_hosts(scan_dict)
    uniqueNets = set([ips[:ips.rfind(".")] for ips in scanned_hosts])
    perform_traceroute(scanned_hosts)
    for un in uniqueNets:
        print (un)
        create_network_graph({k:v for (k,v) in scanned_hosts.items() if un in k},un)
    


    

    
    create_network_graph(scanned_hosts)
    pprint.pprint(allhops)
