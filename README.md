# Network Tracer and Port Scanner

This program serves as a comprehensive network exploration tool. It can scan an IP range to identify active hosts, execute a traceroute on these hosts to discover the network path, perform port scanning to detect open ports, and generate a visual network map to represent these data graphically. The tool utilizes multi-threading for increased efficiency and speed.

## Main Features

1. **Network Scanning**: This tool allows you to specify an IP range, which it then scans to detect active hosts. It does this by sending ICMP echo requests and waiting for responses.

2. **Port Scanning**: For each live host, the script carries out a TCP port scan, checking for open ports. The number of ports to be scanned can be customized, allowing a balance between thoroughness and speed.

3. **Traceroute**: A traceroute is performed on each active host to reveal the network path between the source and destination. The sequence of hops is saved for further use and visualization.

4. **Network Map**: Using the `pygraphviz` library, the program generates a network graph that visualizes the network's structure, including traceroutes and open ports on each host.

5. **Reading from XML**: If you have previously performed a network scan using Nmap and have the data saved in an XML file, this program can read the file to obtain host and open port information.

6. **Saving Results**: The network map data is saved to a JSON file, while the network graph is saved as an SVG file.

Please note: this tool should only be used in an environment where you have permissions to perform such operations. Unauthorized scanning or network analysis can be considered as an intrusion and may be illegal in certain jurisdictions.

## Usage

please note: you need theports.txt file and run the program with sudo. 

```
python main.py [-x XML_FILE] [-i IP_RANGE] [-p NUM_PORTS] [-o OUTPUT_FILE]
```
Where:

* `-x, --xml`: Specify the Nmap generated XML input file, e.g. `outputscan.xml`. This uses the values from this file, skipping a manual scan.
* `-i, --ip_range`: Specify the IP range for scan. You can use `,` or `-` to specify the range, e.g. `192.168.0-5.10-20,50-100`.
* `-p, --num_ports`: Specify the top number of common ports (1 to 8366) to scan when doing a manual scan. Default is 1000.
* `-o, --output`: Save network map to a JSON file. Default is `output_scan.json`.

## Dependencies

The program requires Python 3 and the following libraries: xmltodict, scapy, numpy, multiprocessing, tqdm, pygraphviz, and argparse. Make sure to install these libraries before running the script.
