import xmltodict
import pprint
from scapy.layers.inet import traceroute
from collections import OrderedDict
import pygraphviz as pgv
import socket
import numpy as np
 

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

def get_random_hex_color():
    color = list(np.random.choice(range(40,225),size=3))
    return '#{:02x}{:02x}{:02x}'.format(color[0], color[1], color[2])
    
    

def create_network_graph(scanned_hosts, filename="all"):
    graph = pgv.AGraph(overlap=False, splines="curved", directed=True, rankdir="LR", strict=False)
    n = 0

    for host, data in scanned_hosts.items():
        parent_node = list(data["parentIP"])
        maxHops = len(data["parentIP"])
        #print(f"The MAxIMUM VALUE IS AJSDLKJASLFJDSALJF LAK::::::::::: {maxHops} for the host {host}")
        


        formatedPorts = { "<BR />" +p + ": " + v for p,v in data['theports']} 
        graph.add_node(host, label=f"<IP: {host} \n Ports: {formatedPorts}>", shape='rectangle')
        #graph.add_path(parent_node)
        #graph.add_edges_from(edges, color="red", dir="forward", arrowType="normal")lastHop[:lastHop.rfind(".")] 
        nlist = parent_node
        path_color = get_random_hex_color()
        if len(nlist) > 1:
            fromv = nlist.pop(0)
            
            while len(nlist) > 0:
                tov = nlist.pop(0)
                # lastHop[:lastHop.rfind(".")]
                
                if len(graph.in_edges((fromv,tov))) < 6:
                    if graph.has_edge(fromv,tov, key=f"{fromv}_{tov}") == False:
                        
                        graph.add_edge(fromv, tov, key=f"{fromv}_{tov}_{host}", color=f"{path_color}")
                else:
                    if graph.has_edge(fromv, tov):
                        graph.remove_edges_from(graph.in_edges(tov))
                        graph.add_edge(fromv, tov, key=f"{fromv}_{tov}", penwidth="3", color=f"{path_color}")
                # graph.remove_edges_from(graph.in_edges("172.16.30.1"))   
                # if len(graph.edges(((fromv, tov, f"{fromv}{tov}{len(nlist)}")))) > 5:
                #     print("REMoVing AEJALKDFJALSKJFLAK WEJFEDGE EDG EEDGEEDGDEGEGEGEGEGED")
                #     try:
                #         graph.remove_edge((f"{fromv}{tov}{host}{len(nlist)}"))
                #     finally:
                #         if len(graph.edges((fromv, tov, f"{fromv}{tov}{host}{len(nlist)}a"))) < 1:
                #             graph.add_edge(fromv, tov, f"{fromv}{tov}{host}{len(nlist)}a", color="red", penwidth="3") 
                    # else:
                    #     graph.remove_edges_from((fromv, tov, f"{host}a"))
                    #     graph.add_edge(fromv, tov, f"{host}a", color="red", penwidth="3")
                        
                


                #print(f"NUMBER OF EDGES GOING TO {fromv} to {tov} is {len(graph.edges((fromv, tov)))} !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                fromv = tov
    theset = {}
    for node in graph.nodes():
        print(len(graph.in_edges(node,keys=True)))
        # if len(graph.in_edges(node)) > 6:
            # graph.remove_edges_from(graph.in_edges(node))
        # for edge in graph.in_edges(node):
        #     # theset[host]= edge
        #     print(len(edge))

        #     print("ASDFJADSKLFJADSLFKJZSDLKFJASDLKFJASDLKFJASDLKFJASDLKFJASDLKFJASDLKFJASDLKFJASDLKJFASDLKFASDLKJFASDLKJASDLKJFASDLKJ")
            # graph.delete_edge(edge, key=host)
    # pprint.pprint(sorted(theset))
        
    # graph.add_edges_from(theset, color=f"{path_color}")
    # graph.remove_edges_from(graph.in_edges("172.16.30.1"))            
    print("donewiththathost")


    graph.layout("neato")
    graph.draw(f"graph_{filename}.svg")


if __name__ == '__main__':
    scan_dict = read_xml('outputscan.xml')
    thisip= getMyIP()
    scanned_hosts = get_scanned_hosts(scan_dict)
    uniqueNets = set([ips[:ips.rfind(".")] for ips in scanned_hosts])
    perform_traceroute(scanned_hosts)
    for un in uniqueNets:
        #print (un)
        create_network_graph({k:v for (k,v) in scanned_hosts.items() if un in k},un)
    


    

    
    create_network_graph(scanned_hosts)
    #pprint.pprint(allhops)
