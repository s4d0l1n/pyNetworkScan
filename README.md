# pyNetworkScan

run nmap scan and output to xml file first

sudo nmap [ip range] –oX outputscan.xml 

then run

sudo python pyNetworkScan.py


you need the theports.txt file if you are going to do a scan with the pyNetworkScan instead using a nmap xml file. 
