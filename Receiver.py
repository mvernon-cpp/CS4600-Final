#For task 1
from Crypto.PublicKey import RSA	

#for task 5 - part 1
from base64 import b64decode
import json

#for task 5 - part 2
# from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import sys
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


class Receiver:
	def __init__(self):
		self.name = "Receiver: Bob"
		self.message = ''		#receiver will decrypt sender message to be stored in this message

	def __str__(self):
		return self.name


	
	def generateKeys(self):
		#Task 1
		print('Generating receiver keys')
		key = RSA.generate(2048)
		privateKey = key.export_key()
		outFile = open("privateKeys/receiver.private.key", "wb")
		outFile.write(privateKey)
		outFile.close()

		publicKey = key.publickey().export_key()
		outFile = open("publicKeys/receiver.public.pem", "wb")
		outFile.write(publicKey)
		outFile.close()

	def getData(self):
		#Task 5 - part 1
		file_in = json.loads(open("Transmitted_Data", "r").read())
		self.ciphertext = file_in['ciphertext']
		self.iv = file_in['iv']
		self.encSessionKey = file_in['session key']
		self.mac = file_in['mac']

		# print(self.ciphertext + '\n\n' + self.iv + '\n\n'+ self.encSessionKey + '\n\n'+ self.mac+'\n')

	def decryptMessage(self):
		#Task 5 - part 2
		#decrypt session key first
		try:
			privateKey = RSA.import_key(open("privateKeys/receiver.private.key",'r').read())
			rsa_cipher = PKCS1_OAEP.new(privateKey)

			session_key = rsa_cipher.decrypt(b64decode(self.encSessionKey.encode('utf-8')))
			print("Decrypting session key for receiver")
			# print((session_key))
			# print(str(session_key))
		except (ValueError, KeyError):
			print("No message received or Incorrect decryption")
			sys.exit()


		# Validate the MAC,
		# if the mac is invalid the receiver does not attempt to decrypt the ciphertext
		print("Verifying updated MAC")
		h = HMAC.new(session_key, digestmod=SHA256)
		h.update(bytes(self.ciphertext,'utf-8'))
		try:
			h.verify(b64decode(self.mac.encode('utf-8')))
			print("Valid message")
		except ValueError:
			print("Invalid message")
			sys.exit()

		# Decrypt the ciphertext using the decrypted AES session key
		print("Decrypting message with session key")
		try:
			ivDecode = b64decode(self.iv)
			ctDecode = b64decode(self.ciphertext)
			
			aes_cipher = AES.new(session_key, AES.MODE_CBC, ivDecode)
			plaintext = unpad(aes_cipher.decrypt(ctDecode), AES.block_size)

			self.message = str(plaintext, 'utf-8')
		except (ValueError, KeyError) as e:
			print("Decryption error")
			print(e)