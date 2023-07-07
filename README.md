# pyNetworkScan

you need the theports.txt file if you are going to do a scan with the pyNetworkScan instead using a nmap xml file. 


sudo python pyNetworkScan.py


usage: pyNetworkScan.py [-h] [-x XML] [-i IP_RANGE] [-p NUM_PORTS] [-o OUTPUT]

Network Tracer and Port Scanner

options:
  -h, --help            show this help message and exit
  
  -x XML, --xml XML     Specify the Nmap generated XML input file ie: outputscan.xml. This will use the values from this file skipping a manual scan.
  
  -i IP_RANGE, --ip_range IP_RANGE
  
                        Specify the IP range for scan. You can use , or - to specify the range ie: 192.168.0-5.10-20,50-100
                        
  -p NUM_PORTS, --num_ports NUM_PORTS
  
                        Specify the top number of common ports (1 to 8366) to scan when doing a manual scan, default: 1000
                        
  -o OUTPUT, --output OUTPUT
  
                        save network map to json file, default: output_scan.json
                        

Generate XML file with nmap:


run nmap scan and output to xml file first


sudo nmap [ip range] –oX outputscan.xml 

