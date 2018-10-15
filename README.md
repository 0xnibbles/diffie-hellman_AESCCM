1. As soon as the client connects to the server the two initiate the exchange of keys automatically through the DIFFIE-Hellman protocol
2. Alice (** Server **) generates prime numbers G and P;
3. Bob (** Client **) receives Alice's prime numbers and generates her private key and then the public key and sends the latter to Alice;
4. Alice with BOB public key generates the common shared key and unique to both;
5. The shared key is used in the AES cipher in CCM mode. Only the first 256 bits of the shared key (total of 512 bits) are used because AESCCM allows to use a 256-bit key at most. The nonce is sent along with the message and then it is possible to decipher it. In each message a new nonce is generated;
