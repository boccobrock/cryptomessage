My program is a simple ruby script. Before running, make it executable with:
chmod +x bob.rb

It can then be run as follows:
./bob.rb port (-v)

The port must be a valid integer.
Adding the -v option will make it print out as much information as possible.

It must be run as a script since the CADE machines
have multiple versions of ruby, and the script requires ruby 2.0.0.

Also, it sends an encrypted hash of the public key of bob, not the entire public key.
This is done because of limitations of the openssl API in ruby.
