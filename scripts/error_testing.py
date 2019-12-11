#!/usr/bin/python3
import cse303

# Configure constants and users
cse303.indentation = 80
cse303.verbose = cse303.check_args_verbose()
alice = cse303.UserConfig("alice", "alice_is_awesome")
bob = cse303.UserConfig("bob", "bob_is_awesome")
so1 = "./obj64/all_keys.so"
so2 = "./obj64/odd_key_vals.so"
mrfile = "mr_file_result"

# Create objects with server and client configuration
server = cse303.ServerConfig("./obj64/server.exe", "9999", "rsa", "company.dir", "4", "1024", "1", "1048576", "1048576", "4096", "2", "alice")
client = cse303.ClientConfig("./obj64/client.exe", "localhost", "9999", "localhost.pub")

# Check if we should use spear's server or client
cse303.override_exe(server, client)

# Clean up the file system from the last run, kill active servers
cse303.clean_common_files(server, client)
cse303.killall("server.exe")

# Make the admin and non-admin users
server.pid = cse303.do_cmd("Starting server.", "File not found: company.dir", server.launchcmd())
cse303.waitfor(2)
cse303.line()
cse303.do_cmd("Registering new user alice.", "OK", client.reg(alice))
cse303.do_cmd("Registering new user bob.", "OK", client.reg(bob))
cse303.line()

# Make some keys and insert them
for i in range(1, 9):
    cse303.build_file_as("k"+str(i), str(i))
    cse303.do_cmd("Setting key k" + str(i) + ".", "OK", client.kvI(alice, "k" + str(i), "k" + str(i)))
    print("k",str(i))
    cse303.delfile("k"+str(i))
cse303.line()

# Test that registration of functions properly authenticates
cse303.do_cmd("Registering function.", "OK", client.kvF(alice, "all_keys", so1))
cse303.do_cmd("Re-registering function.", "ERR_FUNC", client.kvF(alice, "all_keys", so1))
cse303.do_cmd("Registering function from bob.", "ERR_LOGIN", client.kvF(bob, "mr2", so1))
cse303.line()

# Bob should be able to invoke a function
print(mrfile)
cse303.do_cmd("Executing map/reduce.", "OK", client.kMR(bob, "all_keys", mrfile))
