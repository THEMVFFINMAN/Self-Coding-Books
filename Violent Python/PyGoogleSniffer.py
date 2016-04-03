import argparse
from scapy.all import *
def findGoogle(pkt):

	if pkt.haslayer(Raw):
		payload = pkt.getlayer(Raw).load

		if 'GET' in payload:
			if 'google' in payload:
				r = re.findall(r'(?i)\&q=(.*?)\&', payload)
 				
 				if r:
					search = r[0].split('&')[0]
					search = search.replace('q=', '').\
						replace('+', ' ').replace('%20', ' ')
					print '[+] Searched For: ' + search

def main():
	parser = argparse.ArgumentParser(description='Google search sniffer')
	parser.add_argument('-i', dest='interface', type=str, help='Interface')

	args = parser.parse_args()

	if args.interface == None:
		print parser.print_help()
		exit(0)
	else:
		conf.iface = args.interface

	try:
		print '[*] Starting Google Sniffer.'
		sniff(filter='tcp port 80', prn=findGoogle)
	except KeyboardInterrupt:
		exit(0)

if __name__ == '__main__':
	main()
