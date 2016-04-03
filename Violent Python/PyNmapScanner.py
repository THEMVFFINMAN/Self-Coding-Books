import nmap, argparse
from threading import Thread

def nmapScan(tgtHost, tgtPort):
	nScan = nmap.PortScanner()
	nScan.scan(tgtHost,tgtPort)
	state=nScan[tgtHost]['tcp'][int(tgtPort)]['state']
	print " [*] " + tgtHost + " tcp/"+tgtPort +" "+state

def main():
	parser = argparse.ArgumentParser(description="A simple Python port scanner using the nmap library")
	parser.add_argument('-H', type=str, help='specify target host')
	parser.add_argument('-p', metavar='N', type=str, nargs='+', help='specify port numbers')
	args = parser.parse_args()

	tgtHost = args.H
	tgtPorts = args.p

	if (tgtHost == None) | (tgtPorts[0] == None):
		print '[-] You must specify a target host and port[s].'
		exit(0)

	for tgtPort in tgtPorts:
		t = Thread(target=nmapScan, args=(tgtHost, tgtPort))
 		t.start()

if __name__ == '__main__':
	main()
