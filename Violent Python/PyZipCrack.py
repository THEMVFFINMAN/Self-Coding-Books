import zipfile, sys, os
from threading import Thread

def validateFile(fileName):
	if not os.path.isfile(fileName):
		print '[-] ' + fileName + ' does not exist.'
		exit(0)
	if not os.access(fileName, os.R_OK):
		print '[-] ' + fileName + ' access denied.'
 		exit(0)

def validateFiles():
  	if len(sys.argv) == 3:
  		for fileName in range(1,3):
  			print sys.argv[fileName]
  			validateFile(sys.argv[fileName])
	else:
		print '[-] Incorrect file amount'
 		exit(0)

def extractFile(zFile, password):
	try:
		zFile.extractall(pwd=password)
		print '[+] Found password: ' + password + '\n'
 	except:
 		pass

def main():
	validateFiles()
	zFile = zipfile.ZipFile(sys.argv[1])
	passFile = open(sys.argv[2])
	for line in passFile.readlines():
		password = line.strip('\n')
		t = Thread(target=extractFile, args=(zFile, password))
		t.start()
	
if __name__ == '__main__':
	main()
