import Sender
import Receiver

def main():
	s = Sender.Sender()
	r = Receiver.Receiver()


	#generate RSA public key from sender and Receiver
	print('*'*16)
	s.generateKeys()
	r.generateKeys()
	print('*'*16)

	#encrypt sender's message
	s.readMessageFile()

	s.encryptMessage()
	s.encryptAESKey()
	s.generateMAC()

	s.writeData()

	#get sender's message and decrypt it
	r.getData()
	r.decryptMessage()

	#verify messages are the same
	print("\nMessage sent:\n" + s.message)
	print("\nMessage received:\n" +r.message)

if __name__=='__main__':
	main()