This simple protocol uses three sets of public/private keys. One for alice, one for bob, and another for C.
C is the certificate authority, which for simplicity is controlled my bob. Use makekeys.rb to make a pair of keys, or use the provided keys.
Bob is run as the server, and Alice is a client. Run bob.rb, choose a port, and then alice can connect to bob to send the message.txt to bob.
