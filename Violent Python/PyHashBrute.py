import crypt

def testPass(cryptPass):
	# In this case the salt is the first two letters of the hash
	salt = cryptPass[0:2]

	#Opens the dictionary read only
	dictFile = open('dictionary.txt','r')

	for word in dictFile.readlines():
 		word = word.strip('\n')

 		#Hashes the words in the dictionary and checks if it matches the user's hash
 		cryptWord = crypt.crypt(word,salt)
 	
 		if (cryptWord == cryptPass):
 			print "[+] Found Password: "+word+"\n"
 			return

	print "[-] Password Not Found.\n"
	return

def main():
	passFile = open('passwords.txt')
	for line in passFile.readlines():
 		if ":" in line:
 			
		 	user = line.split(':')[0]
		 	cryptPass = line.split(':')[1].strip(' ').strip('\n')
		 	print "[*] Cracking Password For: "+user
		 	testPass(cryptPass)
# So the point of this is if I use this file as a module in another file,
# That it won't run this file as the main program. But in this case if it
# is the main program, it will run.	 	
if __name__ == "__main__":
	main()
