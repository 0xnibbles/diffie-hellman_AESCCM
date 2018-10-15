
'''
Made by: Eduardo Mendes-Silva aka eduardommsi
Date: 7/12/17
Version 1.0

Bob is a client
'''

import asyncio
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from Crypto.Random import get_random_bytes


class Client:
    """ A class that implements the functionality of a CLIENT. """
    def __init__(self, name=b''):
        """ Class builder. Receives the client's name"""
        self.name = name

    def initHandshake(self):
        str = 'PHello'
        return str.encode()

    def initmsg(self):
        """ Initial Message """
        str = "Hello from %r!" % (self.name)
        return str.encode()

    def respond(self, msg):
        """ Process a message (sent by the SERVER)
         Prints the received message and reads from the answer from the keyboard. """
        print('Received: %r' % msg.decode())
        new = input().encode()
        return new
    '''
        Generates Keys
    '''
    def generatePrivateKey(self,parameters):
        #time.sleep(0.7)
        private_key = parameters.generate_private_key()
        return private_key
    def generatePublicKey(self,private):
        public_key = private.public_key()
        return public_key
    def getPublicValue(self,public):
        key= public.public_numbers().y
        return key
    def generateSharedKey(self,private_key,peer_public_keyB):
        shared_key = private_key.exchange(peer_public_keyB)
        return shared_key
    def decomposePeerKey(self,pubBobKey,pn): # Through Alice's public key creates object that allows you to compute the shared key
        peer_public_numbers = dh.DHPublicNumbers(pubBobKey, pn)
        peer_public_keyBob = peer_public_numbers.public_key(default_backend())
        return peer_public_keyBob
    '''
        Encryption
    '''
    def encrypt(self,key,msg):

        aesccm = AESCCM(key)
        nonce = get_random_bytes(13)
        ct = aesccm.encrypt(nonce, msg,None)
        return (nonce,ct)

        return msg
    def decrypt(self,key,msg,nonce):
        aesccm = AESCCM(key)
        dt = aesccm.decrypt(nonce, msg, None)
        return dt


'''
    Assinchronous Code
'''


@asyncio.coroutine
def tcp_echo_client(loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()

    reader, writer = yield from asyncio.open_connection('127.0.0.1', 9999,
                                                        loop=loop)

    data = b'P'
    client = Client("Cliente 1")
    msg = client.initHandshake() # Initiates key exchange process
    while len(data)>0:
        if msg:

            writer.write(msg)

            if msg[:1] == b'E': break
            data = yield from reader.read(1000)
            if len(data)>0 :
                if data[:1] == b'P': # receives parameters p and g and sends the public key

                    '''
                        1º - Receive parameters: p and g
                        2º - Generates Private Key: pivKey
                        3º - Generates Public Key pubKey
                        4º - Send Public Key
                    '''
                    #1º
                    g = int(data[1:2].decode())
                    p = int(data[2:].decode())
                    pn = dh.DHParameterNumbers(p, g)
                    parameters = pn.parameters(default_backend())

                    #2º and 3º
                    prvtKey = client.generatePrivateKey(parameters)
                    pblcKey = client.generatePublicKey(prvtKey)
                    pblcValue = client.getPublicValue(pblcKey)

                    #4º
                    msg = 'K' + str(pblcValue)
                    msg = msg.encode()


                elif data[:1]==b'K': # receives Alice public key and initiates secure communication
                    '''
                        1º - Receives Alice's Public Key: aliceKey
                        2º - Create Shared Key: sharedKey
                        3º - Send msg of encrypted Hello (Letter S -> means secure)
                    '''
                    #1º
                    serverKey = data[1:].decode()
                    peer_public_key = client.decomposePeerKey(int(data[1:].decode()),pn) # through Alice's public key creates object that allows you to compute the shared key
                    #2º
                    shared_key = client.generateSharedKey(prvtKey,peer_public_key)
                    #3º
                    msg = client.initmsg()
                    nonce,msg = client.encrypt(shared_key[:32],msg)
                    msg = b'S' + nonce + msg


                elif data[:1]==b'S':
                    '''
                        Secure communication
                         1º - Decipher msg with sharedKey
                         2º - Encrypt with sharedKey
                    '''
                    #1º
                    msg = client.decrypt(shared_key[:32],data[14:],data[1:14])
                    msg = client.respond(msg)
                    #2º
                    nonce,msg = client.encrypt(shared_key[:32],msg)
                    msg = b'S' + nonce +msg
            else:
                writer.write(b'E')
                break
        else:
            writer.write(b'E')
            break
    print('Socket closed!')
    writer.close()



loop = asyncio.get_event_loop()
loop.run_until_complete(tcp_echo_client())
