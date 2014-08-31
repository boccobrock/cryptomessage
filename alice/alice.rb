#!/usr/local/stow/ruby/amd64_linux26/ruby-2.0.0-p0/bin/ruby
require 'socket'
require 'openssl'

abort 'Usage: alice.rb host port (-v). Sends message in message.txt' if !ARGV[0] && !ARGV[1]

def puts_verbose message
    if ARGV[2] && ARGV[2] == "-v"
        puts message
    end
end

def get_hex str
    # read the string as hex, put spaces after every pair, and add newlines every 11th pair
    str.unpack('H*').first.gsub(/(..)/,'\1 ').gsub(/(.{63})/,"\\1\n").rstrip
end

def verify_key str
    puts_verbose "Alice: reading c public key and decrypting bob public key hash"

    # Load the C public key
    ckey = OpenSSL::PKey::RSA.new File.read 'c_public.pem'
    puts_verbose "Alice: c public key: \n"+ckey.to_pem+"\n"

    # Read in our public key and then private encrypt it with C
    bobPublic = ckey.public_decrypt str

    puts_verbose "Alice: recieved hash: \n"+bobPublic

    # Read in our public key and then private encrypt the hash
    bobPublicStr = File.read 'bob_public.pem'
    hash = Digest::SHA1.base64digest bobPublicStr
    puts_verbose "Alice: computed hash: \n"+hash

    return bobPublic == hash
end

def make_secure_message
    # First hash the message and encrypt that hash with our private key
    plain = File.read 'message.txt'
    puts "Alice: message to be sent: \n"+plain+"\n"

    hash = Digest::SHA1.base64digest plain
    puts_verbose "Alice: SHA1 hash of message: \n"+get_hex(hash)+"\n\n"

    akey = OpenSSL::PKey::RSA.new File.read 'alice_private.pem'
    encryptedHash = akey.private_encrypt hash
    puts_verbose "Alice: encrypted hash: \n"+get_hex(encryptedHash)+"\n\n"

    # First concatenation is our message and the encrypted hash
    cat = encryptedHash + plain

    # Now create a symmetric key and encrypt cat
    deskey = OpenSSL::Cipher::Cipher.new("des-ede3")
    deskey.encrypt
    skey = deskey.random_key
    puts_verbose "Alice: symmetric key: \n"+get_hex(skey)+"\n\n"

    encryptedMessage = deskey.update(cat) + deskey.final
    puts_verbose "Alice: encrypted message: \n"+get_hex(encryptedMessage)+"\n\n"

    # Encrypt the symmetric key with bobs public key
    bkey = OpenSSL::PKey::RSA.new File.read 'bob_public.pem'
    encryptedSKey = bkey.public_encrypt skey
    puts_verbose "Alice: encrypted symmetric key: \n"+get_hex(encryptedSKey)+"\n\n"

    # Second concatenation is the encrypted symmetric key and the encrypted message
    encryptedSKey + encryptedMessage
end

def start_connection host, port
    # Create a socket to bob
    socket = TCPSocket.new host, port
    puts_verbose "Alice: sending HELLO"
    socket.send "HELLO\n", 0

    # Load the data into a buffer
    response = socket.gets

    puts_verbose "Alice: bobs encrypted key: \n"+get_hex(response)+"\n\n"

    # Decrypt the key received
    unless verify_key response.chomp
        puts_verbose "Alice: Hashes did not match, closing socket"
        socket.close
        return
    end

    puts_verbose "Alice: Hashes did match\n\n"

    # Now send our secured message
    message = make_secure_message
    puts_verbose "Alice: entire secure message: \n"+get_hex(message)+"\n\n"
    socket.write message
    puts "Alice: Message sent!"

    puts_verbose "Alice: closing socket"
    socket.close

rescue Exception => e
    # If we get an error, let alice know and then close the socket
    puts_verbose e 
    puts_verbose e.backtrace
    socket.write "Alice: Ambiguous Error"
    socket.close
end

puts "Alice: connecting to #{ARGV[0]} on port #{ARGV[1]}"
start_connection ARGV[0], ARGV[1]
