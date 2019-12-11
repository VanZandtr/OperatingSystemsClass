#!/usr/bin/python3
import cse303

# Configure constants and users
cse303.indentation = 80
cse303.verbose = cse303.check_args_verbose()
alice = cse303.UserConfig("alice", "alice_is_awesome")
fakealice = cse303.UserConfig("alice", "not_alice_password")
bob = cse303.UserConfig("bob", "bob_is_the_best")
afile1 = "client/client_args.h"
allfile = "allfile"

# Create objects with server and client configuration
server = cse303.ServerConfig("./obj64/server.exe", "9999", "rsa", "company.dir")
client = cse303.ClientConfig("./obj64/client.exe", "localhost", "9999", "localhost.pub")

# Check if we should use spear's server or client
cse303.override_exe(server, client)

# Clean up the file system from the last run, kill active servers
cse303.clean_common_files(server, client)
cse303.killall("server.exe")

# Register users, put content, persist
server.pid = cse303.do_cmd("Starting server.", "File not found: " + server.dirfile, server.launchcmd())
cse303.waitfor(2)
cse303.line()
cse303.do_cmd("Registering new user alice.", "OK", client.reg(alice))
cse303.do_cmd("Setting alice's content.", "OK", client.setC(alice, afile1))
cse303.do_cmd("Checking alice's content.", "OK", client.getC(alice, alice.name))
cse303.check_file_result(afile1, alice.name)
cse303.do_cmd("Getting all users to make sure it's just alice.", "OK", client.getA(alice, allfile))
cse303.check_file_list(allfile, [alice.name])
cse303.do_cmd("Instructing server to persist data.", "OK", client.persist(alice))
cse303.line()
cse303.do_cmd("Stopping server.", "OK", client.bye(alice))
cse303.await_server("Waiting for server to shut down.", "Server terminated", server.pid)
cse303.line()

# Ensure persistentce works, test other features
server.pid = cse303.do_cmd("Restarting server to check persistence.", "Loaded: " + server.dirfile, server.launchcmd())
cse303.waitfor(2)
cse303.line()
cse303.do_cmd("Re-registering alice.", "ERR_USER_EXISTS", client.reg(alice))
cse303.do_cmd("Checking alice's old content.", "OK", client.getC(alice, alice.name))
cse303.check_file_result(afile1, alice.name)
cse303.do_cmd("Attempting access with bad password.", "ERR_LOGIN", client.getC(fakealice, alice.name))
cse303.do_cmd("Attempting access with bad user.", "ERR_LOGIN", client.getC(bob, alice.name))
cse303.do_cmd("Registering user bob.", "OK", client.reg(bob))
cse303.do_cmd("Attempting to access alice's data by bob.", "OK", client.getC(bob, alice.name))
cse303.check_file_result(afile1, alice.name)
cse303.do_cmd("Getting bob's nonexistent data.", "ERR_NO_DATA", client.getC(bob, bob.name))
cse303.do_cmd("Getting all users to make sure it's alice and bob.", "OK", client.getA(alice, allfile))
cse303.check_file_list(allfile, [bob.name, alice.name])
cse303.do_cmd("Getting all users to make sure it's alice and bob.", "OK", client.getA(alice, allfile))
cse303.check_file_list(allfile, [alice.name, bob.name])
cse303.do_cmd("Instructing server to persist data.", "OK", client.persist(alice))
cse303.line()

# Clean up
cse303.do_cmd("Stopping server.", "OK", client.bye(alice))
cse303.await_server("Waiting for server to shut down.", "Server terminated", server.pid)
cse303.line()
cse303.clean_common_files(server, client)