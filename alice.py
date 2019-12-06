'''
Made by: s4nkx0k
Date: 7/12/17
Version 1.0

Alice is a server
'''


import asyncio
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from Crypto.Random import get_random_bytes


conn_cnt = 0


class ServerWorker(object):
    """ Class that implements the SERVER functionality. """
    def __init__(self, cnt):
        """ Class builder. """
        self.id = cnt
    def respond(self, msg, peername):
        """ Process a message (sent by CLIENT)"""
        assert len(msg)>0, "empty message!!!"
        print('%d :%r' % (self.id,msg.decode()))
        return msg
    '''
        Generates keys
    '''
    def getParams(self):
        parameters = dh.generate_parameters(generator=2, key_size=512,backend=default_backend())
        return parameters
    def generatePrivateKey(self,parameters):
        private_key = parameters.generate_private_key()
        return private_key
    def generatePublicKey(self,private_key):
        public_key = private_key.public_key().public_numbers().y
        return public_key
    def generateSharedKey(self,peer_public_key,private_key):
        shared_key = private_key.exchange(peer_public_key)
        return shared_key
    def generateSharedKey(self,private_key,peer_public_key):
        shared_key = private_key.exchange(peer_public_key)
        return shared_key
    def decomposePeerKey(self,pubKey,pn): # Through Bob's public key creates object that allows computing the shared key
        peer_public_numbers = dh.DHPublicNumbers(pubKey, pn)
        peer_public_key = peer_public_numbers.public_key(default_backend())
        return peer_public_key
    '''
        Encryption
    '''
    def encrypt(self,key,msg):
        aesccm = AESCCM(key)
        nonce = get_random_bytes(13)
        ct = aesccm.encrypt(nonce, msg, None)
        return (nonce,ct)
    def decrypt(self,key,msg,nonce):
        aesccm = AESCCM(key)
        dt = aesccm.decrypt(nonce, msg, None)
        return dt

'''
    Assinchronous Code
'''

@asyncio.coroutine
def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    srvwrk = ServerWorker(conn_cnt)
    data = yield from reader.read(1000)
    while True:
        if data[:1]==b'E': break
        if not data: continue
        if data[:1]==b'P': # Generates P and G parameters with Diffie-Hellman protocol
            '''
                1º - Creates parametes: p and g
                2º - Sends the parameters:
            '''
            #1º
            parameters = srvwrk.getParams()
            p = parameters.parameter_numbers().p
            g = parameters.parameter_numbers().g
            pn = dh.DHParameterNumbers(p, g)

            #2º

            res ='P'+str(g)+str(p)
            res = res.encode()


        elif data[:1]==b'K': # recebe chave pública do Bob e envia a sua chave pública
            '''
                1º - Receive Bob's Public Key: bobKey
                2º - Creates Private Key:privKey
                3º - Creates Public Key: pubKey
                4º - Sends Public Key
                5º - Creates Shared Key: sharedKey
            '''
            #1º
            peer_public_key = srvwrk.decomposePeerKey(int(data[1:].decode()),pn)
            #2º e 3º
            prvtKey = srvwrk.generatePrivateKey(parameters)
            pblcKey = srvwrk.generatePublicKey(prvtKey)

            #4º
            res ='K'+str(pblcKey)
            res = res.encode()
            #5º
            shared_key = srvwrk.generateSharedKey(prvtKey,peer_public_key)


        elif data[:1]==b'S':
            '''
                Secure Communication
                1º - Decipher msg with sharedKey
                2º - Cipher with sharedKey
            '''

            #1º
            msg = srvwrk.decrypt(shared_key[:32],data[14:],data[1:14])
            addr = writer.get_extra_info('peername')
            res = srvwrk.respond(msg, addr)
            #2º
            nonce,res = srvwrk.encrypt(shared_key[:32],res)

            res = b'S'+ nonce +res

        if not res: break

        writer.write(res)
        yield from writer.drain()
        data = yield from reader.read(1000)
    print("[%d]" % srvwrk.id)
    writer.close()

loop = asyncio.get_event_loop()
coro = asyncio.start_server(handle_echo, '127.0.0.1', 9999, loop=loop)
server = loop.run_until_complete(coro)

# Serve requests until Ctrl+C is pressed
print('Serving on {}'.format(server.sockets[0].getsockname()))
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

# Close the server
server.close()
loop.run_until_complete(server.wait_closed())
loop.close()
print('FINISH!')
