import argparse
import logging
import time
import Queue
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from threading import *
import sys

# Where you want to save your html file
html_file = "dashboard.html"
src_port = 400
# Thread dictionary
Hosts = dict()

# My Host class which makes working with threads easier
class Host:
    tcp_ports = set()
    udp_ports = set()
    traceroute = set()
    ICMP_ping = False
    name = ""
    def __init__(self, pname):
        self.name = pname
        self.traceroute = set()
        self.tcp_ports = set()
        self.udp_ports = set()

def tcpScan(tgtHost, tgtPort):
    # This is where we perform the TCP scan
    tcp_connect_scan_resp = sr1(IP(dst=tgtHost)/TCP(sport=src_port,dport=tgtPort,flags="S"),timeout=3, verbose=0)

    # If a bad response, than it was closed
    if(str(type(tcp_connect_scan_resp))!="<type 'NoneType'>") and tcp_connect_scan_resp.haslayer(TCP):
        if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
            Hosts[tgtHost].tcp_ports.add(tgtPort)

def udpScan(tgtHost, tgtPort):
    # Sends an UDP request, if no response is received the port is identified as being open
    ans = sr1(IP(dst=tgtHost)/UDP(dport=tgtPort),timeout=5,verbose=0)
    time.sleep(1)
    # We can identify all ports that don't return an ICMP host-unreachable reply
    if ans == None:
        Hosts[tgtHost].udp_ports.add(tgtPort)

def icmpScan(tgtHost, tgtPort):
    # Sends an ICMP ping
    ICMP_connect_scan_resp,unans=sr(IP(dst=tgtHost)/ICMP(), verbose=0)
    # If it comes back successfully than it was a successful ICMP ping
    if(str(type(ICMP_connect_scan_resp))!="<type 'NoneType'>"):
        Hosts[tgtHost].ICMP_ping = True

def traceRoute(tgtHost, tgtPort):
    ttl = 1
    while 1:
        p=sr1(IP(dst=tgtHost,ttl=ttl)/ICMP(id=os.getpid()), verbose=0)
        # if time exceeded due to TTL exceeded
        if p[ICMP].type == 11 and p[ICMP].code == 0:
            traceroute = "{} -> {}".format(ttl, p.src)
            Hosts[tgtHost].traceroute.add(traceroute)
            ttl += 1
        # Or if the type is correct
        elif p[ICMP].type == 0:
            traceroute = "{} -> {}".format(ttl, p.src)
            Hosts[tgtHost].traceroute.add(traceroute) 
            break

def portScan(tgtHosts, tgtPorts):
    # Simple for loop where I run through all the hosts and ports
    # and thread them
    for tgtHost in tgtHosts:
        for tgtPort in tgtPorts:
            t1 = Thread(target=tcpScan, args=(tgtHost, int(tgtPort)))
            t1.start()
            t2 = Thread(target=udpScan, args=(tgtHost, int(tgtPort)))
            t2.start()
        t3 = Thread(target=icmpScan, args=(tgtHost, 11))
        t3.start()
        t4 = Thread(target=traceRoute, args=(tgtHost, 7))
        t4.start()
    time.sleep(20)

def printHosts():
    # A simple printing function for the command line
    for host_name in Hosts:
        host = Hosts[host_name]
        print "[+] Host: {}".format(host.name)
        if (host.ICMP_ping):
            print "[+] Successful ICMP Ping"
        else:
            print "[-] Could not be ICMP Pinged"
        for tcp_port in host.tcp_ports:
            print "[+] TCP Ports: {} OPEN".format(tcp_port)
        for udp_port in host.udp_ports:
            print "[+] UDP Ports: {} OPEN".format(udp_port)
        for traceroute in host.traceroute:
            print "[+] TraceRoute: {}".format(traceroute)
        
    print "[+] Finished"
    sys.exit(0)

def htmlHosts():
    dirty_html = ""

    # This is a long and convoluted way of printing everything to an HTML file

    begin = """
<!DOCTYPE html>
<html>
<head>
<title>Hosts</title>
<style>
select {
  background-color: #507FB3;
  color: #F0F9FC;
  font-size: 14px;
}
a {
    color: white;
}
</style>
</head>
<body style="background-color:#0151AB">

"""
    dirty_html += begin
    for host_name in Hosts:
        host = Hosts[host_name]
        ICMP_string = ""
        if (host.ICMP_ping):
            ICMP_string = "Successful"
        else:
            ICMP_string = "Failed"

        host_html = """
<center>
<h1 style="color:#ffb7b9;text-decoration: underline;">
{}</h1>
</center>
<table border= "1" class="sortable" align="center" style="color:#F0F9FC;font-size:19px">
<tr style="font-weight:bold; font-size:24px; text-decoration:underline; color: #FFEFCC">
<td>ICMP Ping</td>
</tr>
<tr>
<td>{}</td></tr>
""".format(host_name, ICMP_string)

        dirty_html += host_html
        host_html = """
<tr style="font-weight:bold; font-size:24px; text-decoration:underline; color: #FFEFCC">
<td>TCP Ports Open</td>
</tr>
<tr>
<td>
"""
        for tcp_port in host.tcp_ports:
            host_html += "{} ".format(tcp_port)

        host_html += "</td></tr>"
        dirty_html += host_html
        host_html = """
<tr style="font-weight:bold; font-size:24px; text-decoration:underline; color: #FFEFCC">
<td>UDP Ports Open</td>
</tr>
<tr>
<td>
"""
        for udp_port in host.udp_ports:
            host_html += "{} ".format(udp_port)

        host_html += "</td></tr>"

        dirty_html += host_html
        host_html = """
<tr style="font-weight:bold; font-size:24px; text-decoration:underline; color: #FFEFCC">
<td>TraceRoute</td>
</tr>
<tr>
<td>
"""
        for traceroute in host.traceroute:
            host_html += "{} ".format(traceroute)

        host_html += "</td></tr></table>"
        dirty_html += host_html

    dirty_html += "</body></html>"

    html_file = open(html_file, "w")
    html_file.write(dirty_html)
    html_file.close()
        
    print "[+] Html Written"

def main(): #Uses arg parse, gets a list of hosts or ports, pretty simple to use 
        parser = argparse.ArgumentParser(description = 'A simple Python port scanner.') 
        parser.add_argument('-H', type = str, nargs = '+', help = 'website or ip address') 
        parser.add_argument('-p', metavar = 'N', type = int, nargs = '+', help = 'one or several port numbers') 
        args = parser.parse_args()

        tgtHosts = args.H


        tgtPorts = args.p

        if (tgtHosts == None) or(tgtPorts == None):
            print '[-] You must specify a target host and port[s].'
            exit(0)

        for tgtHost in tgtHosts:
            new_host = Host(tgtHost)
            Hosts[tgtHost] = new_host

        portScan(tgtHosts, tgtPorts)
        htmlHosts()
        printHosts()
        

if __name__ == '__main__':
    main()
