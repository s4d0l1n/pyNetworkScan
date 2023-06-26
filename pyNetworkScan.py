import xmltodict
import pprint
from scapy.layers.inet import traceroute
from collections import OrderedDict
import pygraphviz as pgv
import socket

def read_xml(file_name):
    with open(file_name) as file:
        return xmltodict.parse(file.read())


def get_scanned_hosts(scan_dict, net=""):
    scanned_hosts = {}

    for host in scan_dict['nmaprun']['host']:
        address = host['address']['@addr'] if type(host['address']) is not list else host['address'][0]['@addr']
        ports = host['ports']['port'] if "port" in host['ports'] else []

        open_ports = get_open_ports(ports)

        scanned_hosts[address] = {"theports": open_ports, "parentIP": ""}

    return scanned_hosts


def get_open_ports(ports):
    open_ports = {}

    if isinstance(ports, list):
        for port in ports:
            open_ports[port.get('@portid')] = port.get('service').get('@name')
    else:
        open_ports[ports['@portid']] = ports['service']['@name']

    return list(open_ports.items())


def perform_traceroute(scanned_hosts):
    for host in scanned_hosts.keys():
        result, unans = traceroute(host, maxttl=6, verbose=None)
        print("ASFKJASLDKFJASDLKFJZSDLKFJSZDLK:JASDLKJASDLJKASDJKF")
        unans.show()
        print("ASJFDASFLKAJSDFLKASDFLKASDALSDKFJASDLKFJASDLKFJ")
        prevhop = [host]
        if len(unans) > 0:
            prevhop = [
                keyb
                for trace in result.get_trace().values()
                for sub_trace in trace.values()
                for keyb in sub_trace if type(keyb) != bool
                ]
            pprint.pprint(prevhop)
        scanned_hosts[host]["parentIP"] = prevhop


def create_network_graph(scanned_hosts, filename="all"):
    graph = pgv.AGraph(overlap=False, splines="curved")

    for host, data in scanned_hosts.items():
        parent_node = list(data["parentIP"])
        lastHop = parent_node[-1]
        # print("*********************************************************************************")
        # lastHop = lastHop[:lastHop.rfind(".")] + ".0"
        # print(lastHop[:lastHop.rfind(".")] + ".0")
        # print("*********************************************************************************")
        # if len(parent_node) > 0 : parent_node.insert(-1,lastHop) 
        # else: 
        #     parent_node.insert(0,lastHop) 
        pprint.pprint(parent_node)
        edges = list(zip(parent_node, parent_node[1:]))
        print("edgestart")
        pprint.pprint(edges)
        print("edgeend")

        #graph.add_edge(host, host[:host.rfind(".")], color="red", dir="forward", arrowType="normal")
        graph.add_node(host, label=f"IP: {host} \n Ports: {data['theports']}", shape='rectangle')
        graph.add_edges_from(edges, color="red", dir="forward", arrowType="normal")


    graph.layout("neato")
    graph.draw(f"graph_{filename}.svg")


if __name__ == '__main__':
    scan_dict = read_xml('outputscan.xml')
    
    scanned_hosts = get_scanned_hosts(scan_dict)
    uniqueNets = set([ips[:ips.rfind(".")] for ips in scanned_hosts])
    perform_traceroute(scanned_hosts)
    for un in uniqueNets:
        print (un)
        create_network_graph({k:v for (k,v) in scanned_hosts.items() if un in k},un)
    


    

    
    create_network_graph(scanned_hosts)
