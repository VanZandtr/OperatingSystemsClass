#!/usr/bin/python3
import cse303

# Configure constants and users
cse303.indentation = 80
cse303.verbose = cse303.check_args_verbose()
alice = cse303.UserConfig("alice", "alice_is_awesome")
afile1 = "server/server_args.h"
afile2 = "ofiles/net.o"
allfile = "allfile"

# Create objects with server and client configuration
server = cse303.ServerConfig("./obj64/server.exe", "9999", "rsa", "company.dir", "4", "1024")
client = cse303.ClientConfig("./obj64/client.exe", "localhost", "9999", "localhost.pub")

# Check if we should use spear's server or client
cse303.override_exe(server, client)

# Clean up the file system from the last run, kill active servers
cse303.clean_common_files(server, client)
cse303.killall("server.exe")

# Test set and get
server.pid = cse303.do_cmd("Starting server.", "File not found: " + server.dirfile, server.launchcmd())
cse303.waitfor(2)
cse303.line()
cse303.do_cmd("Registering new user alice.", "OK", client.reg(alice))
cse303.do_cmd("Setting key k1.", "OK", client.kvI(alice, "k1", afile1))
cse303.do_cmd("Getting key k1.", "OK", client.kvG(alice, "k1"))
cse303.check_file_result(afile1, "k1")
cse303.do_cmd("Setting key k1 again.", "ERR_KEY", client.kvI(alice, "k1", afile1))
cse303.do_cmd("Upserting key k1.", "OKUPD", client.kvU(alice, "k1", afile2))
cse303.do_cmd("Getting key k1.", "OK", client.kvG(alice, "k1"))
cse303.check_file_result(afile2, "k1")
cse303.line()

# Test upsert
cse303.do_cmd("Upserting key k2.", "OKINS", client.kvU(alice, "k2", afile1))
cse303.do_cmd("Getting key k2.", "OK", client.kvG(alice, "k2"))
cse303.check_file_result(afile1, "k2")
cse303.line()

# Test all
cse303.do_cmd("Getting all keys to make sure it's k1 and k2.", "OK", client.kvA(alice, allfile))
cse303.check_file_list(allfile, ["k1", "k2"])
cse303.line()

# Test delete
cse303.do_cmd("Deleting key k2.", "OK", client.kvD(alice, "k2"))
cse303.do_cmd("Getting key k2.", "ERR_KEY", client.kvG(alice, "k2"))
cse303.do_cmd("Getting key k7.", "ERR_KEY", client.kvG(alice, "k7"))
cse303.line()

# Test persist
cse303.do_cmd("Inserting key k3.", "OK", client.kvI(alice, "k3", afile1))
cse303.do_cmd("Instructing server to persist data.", "OK", client.persist(alice))
cse303.line()
cse303.do_cmd("Stopping server.", "OK", client.bye(alice))
cse303.await_server("Waiting for server to shut down.", "Server terminated", server.pid)
cse303.line()

# Ensure persistence works
server.pid = cse303.do_cmd("Restarting server to check persistence.", "Loaded: " + server.dirfile, server.launchcmd())
cse303.waitfor(2)
cse303.line()
cse303.do_cmd("Getting key k1.", "OK", client.kvG(alice, "k1"))
cse303.check_file_result(afile2, "k1")
cse303.do_cmd("Getting key k2.", "ERR_KEY", client.kvG(alice, "k2"))
cse303.do_cmd("Getting key k3.", "OK", client.kvG(alice, "k3"))
cse303.check_file_result(afile1, "k3")
cse303.line()

# Clean up
cse303.do_cmd("Stopping server.", "OK", client.bye(alice))
cse303.await_server("Waiting for server to shut down.", "Server terminated", server.pid)
cse303.line()
cse303.clean_common_files(server, client)