
import xmltodict
import pprint
from scapy.layers.inet import traceroute
from collections import OrderedDict
import pygraphviz as pgv

with open('outputscan.xml') as file:
    my_xml = file.read()
    
scan_dict = xmltodict.parse(my_xml)



scanned_hosts = {}
for x in scan_dict['nmaprun']['host']:
 
    scanned_hosts[str(x['address']['@addr'])] = {"theports" : "", "parentIP" : ""}
    if "port" in x['ports']:
        open_ports = {}
        open_ports = x['ports']['port']
        ports= {}

        for y in x['ports']['port']:

            ports[str(y['@portid'])] = str(y['service']['@name'])

        scanned_hosts[str(x['address']['@addr'])]['theports'] =  ports


pprint.pprint(scanned_hosts.keys())

mygraph = pgv.AGraph(overlap=False, splines="curved")
print(list(scanned_hosts.keys()))
for t in scanned_hosts.keys():
    prevhop = []
    result, unans = traceroute(t, maxttl=6, verbose=None)
    for key in result.get_trace(): #root
        for keya in result.get_trace()[key]: 
            
            for keyb in result.get_trace()[key][keya]:
                
                if type(keyb)!=bool:
                    prevhop.append(keyb)
    try:
        scanned_hosts[t]["parentIP"] =   prevhop.pop(-2)
    except:
        scanned_hosts[t]["parentIP"] =   prevhop.pop()
    pprint.pprint(scanned_hosts[t])           
                
            


for hostnode in scanned_hosts.keys():
    parentnode = scanned_hosts[hostnode]["parentIP"]
    for value in scanned_hosts[hostnode]['theports']:
        pprint.pprint(value)

    mygraph.add_node(hostnode, label=f"IP: {hostnode} \n Ports: {scanned_hosts[hostnode]['theports']}", shape='rectangle')
    mygraph.add_edge(hostnode,parentnode)
    #mygraph.add_edge(hostnode,parentnode)

mygraph.layout("neato")

mygraph.draw("blah.svg")

