#!/usr/local/stow/ruby/amd64_linux26/ruby-2.0.0-p0/bin/ruby
require 'socket'
require 'openssl'

abort 'Usage: bob.rb port (-v)' if !ARGV[0]

bob = TCPServer.new ARGV[0]

def puts_verbose message
    if ARGV[1] && ARGV[1] == "-v"
        puts message
    end
end

def get_hex str
    # read the string as hex, put spaces after every pair, and add newlines every 11th pair
    str.unpack('H*').first.gsub(/(..)/,'\1 ').gsub(/(.{63})/,"\\1\n").rstrip
end

def encrypted_key
    puts_verbose "Bob: reading c private key and encrypting bob public key"

    # Load the C private key
    ckey = OpenSSL::PKey::RSA.new File.read 'c_private.pem'
    puts_verbose "Bob: c private key: \n"+ckey.to_pem+"\n"

    # Read in our public key and then private encrypt the hash
    bobPublic = File.read 'bob_public.pem'
    hash = Digest::SHA1.base64digest bobPublic
    encryptedKey = ckey.private_encrypt hash

    puts_verbose "Bob: public key: \n"+bobPublic+"\n"
    puts_verbose "Bob: encrypted public key hash: \n"+get_hex(encryptedKey)+"\n"

    encryptedKey
end

def read_secure_message message
    # Since we need to split up the method, we need to make sure we can count bytes correctly
    message = message.force_encoding("BINARY")

    # The first 1024 bits (128 bytes) is our encrypted symmetric key
    encryptedSKey = message[0..127]

    # Use our private key to decrypt the key
    bkey = OpenSSL::PKey::RSA.new File.read 'bob_private.pem'
    puts_verbose "Bob: bobs private key: \n"+bkey.to_pem+"\n"

    skey = bkey.private_decrypt encryptedSKey
    puts_verbose "Bob: encrypted symmetric key: \n"+get_hex(encryptedSKey)+"\n\n"
    puts_verbose "Bob: decrypted symmetric key: \n"+get_hex(skey)+"\n\n"

    # With the symmetric key, we can now decrypt the rest of the message
    encryptedMessage = message[128..-1]
    deskey = OpenSSL::Cipher::Cipher.new("des-ede3")
    deskey.decrypt
    deskey.key = skey

    puts_verbose "Bob: encrypted message: \n"+get_hex(encryptedMessage)+"\n\n"
    cat = deskey.update(encryptedMessage) + deskey.final

    # The first 128 bytes is the encrypted hash, the rest is the plaintext message
    cat = cat.force_encoding("BINARY")
    encryptedHash = cat[0..127]
    puts_verbose "Bob: encrypted hash: \n"+get_hex(encryptedHash)+"\n\n"
    plain = cat[128..-1]
    puts "Bob: Message Received: \n"+plain+"\n"

    # Now decrypt the hash with alices public key
    akey = OpenSSL::PKey::RSA.new File.read 'alice_public.pem'
    ahash = akey.public_decrypt encryptedHash
    puts_verbose "Bob: decrypted hash: \n"+get_hex(ahash)+"\n\n"

    # Compute our own hash and compare it with alices
    hash = Digest::SHA1.base64digest plain
    puts_verbose "Bob: computed SHA1 hash of message: \n"+get_hex(hash)+"\n\n"

    if hash == ahash
        puts "Bob: Hashes Matched! Message was authenticated and intact."
    else
        puts "Bob: Hashes did not match! Beware, illegitamate Alice."
    end
end

def start_connection socket
    # Get the string from the socket and make sure its a hello
    request = socket.gets

    puts_verbose "Bob: received #{request}"

    if request != "HELLO\n"
        puts_verbose "Bob:"
        socket.write "Bob: Did not receive HELLO"
        socket.close
        return
    end

    # Now we need to respond with our public key signed by the C private key
    puts_verbose "Bob: sending public key hash encrypted"
    socket.write encrypted_key+"\n\n"

    response = ''
    buffer = ''
    loop do
        puts_verbose "Bob: reading from socket"
        socket.read 4048, buffer
        response << buffer
        break if buffer.size == 0
    end

    puts_verbose "Bob: received secure message: \n"+get_hex(response)+"\n\n"
    read_secure_message response

    puts_verbose "Bob: closing socket"
    socket.close

rescue Exception => e
    # If we get an error, let alice know and then close the socket
    puts e
    puts e.backtrace
    socket.write "Bob: Ambiguous Error"
    socket.close
end

puts "Bob: running on port #{ARGV[0]}"
socket = bob.accept
start_connection socket
