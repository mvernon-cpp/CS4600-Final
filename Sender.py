#For task 1
from Crypto.PublicKey import RSA		#used for public and private key generation

#For task 2
from Crypto.Random import get_random_bytes
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

#For task 3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

#For task 4
from Crypto.Hash import HMAC, SHA256

#For writing to file
import json


class Sender:
	def __init__(self):
		#intilize the sender's message from 'message.txt'
		self.message = self.readMessageFile()
		self.name = "Sender: Alice"
		self.randNumber = self.generateRandomNumber()	#key

		#to be saved in 'Transmitted_Data'
		self.encMessage = ''	#encrypted text from message.txt
		self.iv = ''			#initialization vector of AES.MODE_CBC
		self.encAESkey = ''	#encrypted session key
		self.MAC = ''			#encrypt-then-MAC

	def __str__(self):
		return self.name

	def generateRandomNumber(self):
		return get_random_bytes(16)

	def getMessage(self):
		return self.message

	def readMessageFile(self):
		#default file is message.txt
		file = open("message.txt", "r")
		m = ''

		for line in file:
			m = m + line
		file.close()
		return m

	def generateKeys(self):
		#Task 1
		print('Generating sender keys')
		key = RSA.generate(2048)
		privateKey = key.export_key()
		outFile = open("privateKeys/sender.private.key", "wb")
		outFile.write(privateKey)
		outFile.close()

		publicKey = key.publickey().export_key()
		outFile = open("publicKeys/sender.public.pem", "wb")
		outFile.write(publicKey)
		outFile.close()


	def encryptMessage(self):
		#Task 2
		#using AES CBC mode (ciphertext Block Chaining)
		print('Encrypting message for sender')
		data = bytes(self.message, 'utf-8')

		sessionKey = self.randNumber
		cipher = AES.new(sessionKey, AES.MODE_CBC)
		ct_bytes = cipher.encrypt(pad(data, AES.block_size))

		# self.encMessage = ct_bytes

		iv = b64encode(cipher.iv).decode('utf-8')
		ct = b64encode(ct_bytes).decode('utf-8')

		self.iv = iv
		self.encMessage = ct

		# result = json.dumps({'iv':iv, 'ciphertext':ct})
		# print(result)



	def encryptAESKey(self):
		#Task 3
		#encrypt user's randNumber with receiver's pubklic key
		print('Encrypting AES key for sender')

		sessionKey = self.randNumber

		key = RSA.import_key(open('publicKeys/receiver.public.pem', 'r').read())	# load the key alternatively from the file system
		
		encryptor = PKCS1_OAEP.new(key)
		encKey = encryptor.encrypt(sessionKey)		#encrypt AES session key with receiver's RSA public key

		# self.encAESkey = encKey		#save encrypted key (byte)

		encoded_encKey = b64encode(encKey).decode('utf-8')
		self.encAESkey = encoded_encKey	#save encrypted key (string)
		# print (encoded_encKey)


	def generateMAC(self):
		#Task 4
		#use session key to create hash with SHA256
		print('Generating MAC for sender')

		h = HMAC.new(self.randNumber, digestmod=SHA256)
		h.update( bytes(self.encMessage, encoding="utf-8"))

		self.MAC = b64encode(h.digest()).decode('utf-8')



	def writeData(self):
		#Write all encrypted components to file

		outFile = open("Transmitted_Data", "w")
		data = json.dumps({'ciphertext': self.encMessage, 'iv': self.iv, 'session key':self.encAESkey, 'mac':self.MAC},indent=3)
		# print(data)

		outFile.write(data)
		
		outFile.close()

		print('=='*16)
		print('Transmitted_Data Complete!')
		print('=='*16)
