#!/usr/bin/python3
import cse303

# Configure constants and users
cse303.indentation = 80
cse303.verbose = cse303.check_args_verbose()
alice = cse303.UserConfig("alice", "alice_is_awesome")
afile1 = "common/hashtable.h"
afile2 = "common/vec.h"
allfile = "allfile"
k1 = "k1"
k1file1 = "server/server_args.h"
k1file2 = "server/server.cc"
k2 = "second_key"
k2file1 = "server/server_parsing.h"
k2file2 = "server/server_storage.h"
k3 = "third_key"
k3file1 = "server/server_commands.h"
k3file2 = "common/protocol.h"

# Create objects with server and client configuration
server = cse303.ServerConfig("./obj64/server.exe", "9999", "rsa", "company.dir", "4", "1024")
client = cse303.ClientConfig("./obj64/client.exe", "localhost", "9999", "localhost.pub")

# Check if we should use spear's server or client
cse303.override_exe(server, client)

# Clean up the file system from the last run, kill active servers
cse303.clean_common_files(server, client)
cse303.killall("server.exe")

# Shutting down and restarting should never lose data, even in absence of SAV
# commands.  At the same time, we should see that our company.dir file grows
# accoring to the specification.

# Make sure that REG persists without SAV
server.pid = cse303.do_cmd("Starting server.", "File not found: " + server.dirfile, server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Registering new user alice.", "OK", client.reg(alice))
cse303.do_cmd("Stopping server.", "OK", client.bye(alice))
cse303.await_server("Waiting for server to shut down.", "Server terminated", server.pid)
expect_size1 = 8 + 4 + len(alice.name) + 4 + 16 + 4
cse303.verify_filesize(server.dirfile, expect_size1)
server.pid = cse303.do_cmd("Restarting server to check persistence.", "Loaded: " + server.dirfile, server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Registering new user alice.", "ERR_USER_EXISTS", client.reg(alice))
cse303.do_cmd("Checking alice's content.", "ERR_NO_DATA", client.getC(alice, alice.name))
cse303.line()
cse303.do_cmd("Stopping server.", "OK", client.bye(alice))
cse303.await_server("Waiting for server to shut down.", "Server terminated", server.pid)
cse303.line()

# Make sure that SET persists without sav
server.pid = cse303.do_cmd("Starting server.", "Loaded: " + server.dirfile, server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Setting alice's content.", "OK", client.setC(alice, afile1))
expect_size2 = expect_size1 + 8 + 4 + len("alice") + 4 + cse303.get_len(afile1)
cse303.verify_filesize(server.dirfile, expect_size2)
cse303.do_cmd("Stopping server.", "OK", client.bye(alice))
cse303.await_server("Waiting for server to shut down.", "Server terminated", server.pid)
server.pid = cse303.do_cmd("Restarting server to check persistence.", "Loaded: " + server.dirfile, server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Checking alice's content.", "OK", client.getC(alice, alice.name))
cse303.check_file_result(afile1, alice.name)
cse303.do_cmd("Re-setting alice's content.", "OK", client.setC(alice, afile2))
expect_size3 = expect_size2 + 8 + 4 + len("alice") + 4 + cse303.get_len(afile2)
cse303.verify_filesize(server.dirfile, expect_size3)
cse303.line()
cse303.do_cmd("Stopping server.", "OK", client.bye(alice))
cse303.await_server("Waiting for server to shut down.", "Server terminated", server.pid)
cse303.line()

# Make sure that KVI persists without sav
server.pid = cse303.do_cmd("Starting server.", "Loaded: " + server.dirfile, server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Setting key k1.", "OK", client.kvI(alice, k1, k1file1))
cse303.do_cmd("Stopping server.", "OK", client.bye(alice))
expect_size4 = expect_size3 + 8 + 4 + len(k1) + 4 + cse303.get_len(k1file1)
cse303.verify_filesize(server.dirfile, expect_size4)
cse303.await_server("Waiting for server to shut down.", "Server terminated", server.pid)
server.pid = cse303.do_cmd("Restarting server to check persistence.", "Loaded: " + server.dirfile, server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Checking key k1.", "OK", client.kvG(alice, k1))
cse303.check_file_result(k1file1, k1)
cse303.line()
cse303.do_cmd("Stopping server.", "OK", client.bye(alice))
cse303.await_server("Waiting for server to shut down.", "Server terminated", server.pid)
cse303.line()

# Make sure that KVU persists without sav
server.pid = cse303.do_cmd("Starting server.", "Loaded: " + server.dirfile, server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Upserting key k1.", "OKUPD", client.kvU(alice, k1, k1file2))
expect_size5 = expect_size4 + 8 + 4 + len(k1) + 4 + cse303.get_len(k1file2)
cse303.verify_filesize(server.dirfile, expect_size5 )
cse303.do_cmd("Stopping server.", "OK", client.bye(alice))
cse303.await_server("Waiting for server to shut down.", "Server terminated", server.pid)
server.pid = cse303.do_cmd("Restarting server to check persistence.", "Loaded: " + server.dirfile, server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Checking key k1.", "OK", client.kvG(alice, k1))
cse303.check_file_result(k1file2, k1)
cse303.line()
cse303.do_cmd("Stopping server.", "OK", client.bye(alice))
cse303.await_server("Waiting for server to shut down.", "Server terminated", server.pid)
cse303.line()

# Make sure that KVD persists without sav
server.pid = cse303.do_cmd("Starting server.", "Loaded: " + server.dirfile, server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Deleting key k1.", "OK", client.kvD(alice, k1))
expect_size6 = expect_size5 + 8 + 4 + len(k1)
cse303.verify_filesize(server.dirfile, expect_size6)
cse303.do_cmd("Stopping server.", "OK", client.bye(alice))
cse303.await_server("Waiting for server to shut down.", "Server terminated", server.pid)
server.pid = cse303.do_cmd("Restarting server to check persistence.", "Loaded: " + server.dirfile, server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Checking key k1.", "ERR_KEY", client.kvG(alice, k1))
cse303.line()
cse303.do_cmd("Stopping server.", "OK", client.bye(alice))
cse303.await_server("Waiting for server to shut down.", "Server terminated", server.pid)
cse303.line()

# Now upsert k2 twice and k3 twice
server.pid = cse303.do_cmd("Starting server.", "Loaded: " + server.dirfile, server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Upserting key k2.", "OKINS", client.kvU(alice, k2, k2file1))
cse303.do_cmd("Upserting key k2.", "OKUPD", client.kvU(alice, k2, k2file2))
cse303.do_cmd("Upserting key k3.", "OKINS", client.kvU(alice, k3, k3file1))
cse303.do_cmd("Upserting key k3.", "OKUPD", client.kvU(alice, k3, k3file2))
expect_size7 = expect_size6 + 8 + 4 + len(k2) + 4 + cse303.get_len(k2file1) + 8 + 4 + len(k2) + 4 + cse303.get_len(k2file2) + 8 + 4 + len(k3) + 4 + cse303.get_len(k3file1) + 8 + 4 + len(k3) + 4 + cse303.get_len(k3file2)
cse303.verify_filesize(server.dirfile, expect_size7)
cse303.do_cmd("Stopping server.", "OK", client.bye(alice))
cse303.await_server("Waiting for server to shut down.", "Server terminated", server.pid)
server.pid = cse303.do_cmd("Restarting server to check persistence.", "Loaded: " + server.dirfile, server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Checking key k2.", "OK", client.kvG(alice, k2))
cse303.check_file_result(k2file2, k2)
cse303.do_cmd("Checking key k3.", "OK", client.kvG(alice, k3))
cse303.check_file_result(k3file2, k3)
cse303.line()
cse303.do_cmd("Stopping server.", "OK", client.bye(alice))
cse303.await_server("Waiting for server to shut down.", "Server terminated", server.pid)
#check file here

cse303.line()

# Now condense the file via a SAV command, and make sure it's good
server.pid = cse303.do_cmd("Starting server.", "Loaded: " + server.dirfile, server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Instructing server to persist data.", "OK", client.persist(alice))
# check file here
expect_size8 = 8 + 4 + len(alice.name) + 4 + 16 + 4 + cse303.get_len(afile2) + 8 + 4 + len(k2) + 4 + cse303.get_len(k2file2) + 8 + 4 + len(k3) + 4 + cse303.get_len(k3file2)
cse303.verify_filesize(server.dirfile, expect_size8)
cse303.do_cmd("Checking alice's content.", "OK", client.getC(alice, alice.name))
cse303.check_file_result(afile2, alice.name)
cse303.do_cmd("Checking key k1.", "ERR_KEY", client.kvG(alice, k1))
cse303.do_cmd("Checking key k2.", "OK", client.kvG(alice, k2))
cse303.check_file_result(k2file2, k2)
cse303.do_cmd("Checking key k3.", "OK", client.kvG(alice, k3))
cse303.check_file_result(k3file2, k3)
cse303.line()

# Clean up
cse303.do_cmd("Stopping server.", "OK", client.bye(alice))
cse303.await_server("Waiting for server to shut down.", "Server terminated", server.pid)
cse303.line()
cse303.clean_common_files(server, client)