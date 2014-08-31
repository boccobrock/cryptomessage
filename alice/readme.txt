My program is a simple ruby script. Before running, make it executable with:
chmod +x alice.rb

It can then be run as follows:
./alice.rb host port (-v)

The host may be a IP address or a host name.
Adding the -v option will make it print out as much information as possible.
Ensure that bob is running on the other machine before running alice.

It must be run as a script since the CADE machines
have multiple versions of ruby, and the script requires ruby 2.0.0.

Also, it sends an encrypted hash of the public key of bob, not the entire public key.
This is done because of limitations of the openssl API in ruby.
