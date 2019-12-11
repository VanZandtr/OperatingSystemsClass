#!/usr/bin/python3
import cse303

# Configure constants and users
cse303.indentation = 80
cse303.verbose = cse303.check_args_verbose()
alice = cse303.UserConfig("alice", "alice_is_awesome")
bob = cse303.UserConfig("bob", "bob_is_awesome")
t1kname = "t1k"
cse303.build_file(t1kname, 1024)
allkeys = "allkeys"
topkeys = "topkeys"

# Create objects with server and client configuration
server = cse303.ServerConfig("./obj64/server.exe", "9999", "rsa", "company.dir", "4", "1024", "6", "8192", "8192", "24", "4")
client = cse303.ClientConfig("./obj64/client.exe", "localhost", "9999", "localhost.pub")

# Check if we should use spear's server or client
cse303.override_exe(server, client)

# Clean up the file system from the last run, kill active servers
cse303.clean_common_files(server, client)
cse303.killall("server.exe")

# Register users
server.pid = cse303.do_cmd("Starting server.", "File not found: company.dir", server.launchcmd())
cse303.waitfor(2)
cse303.line()
cse303.do_cmd("Registering new user alice.", "OK", client.reg(alice))
cse303.do_cmd("Registering new user bob.", "OK", client.reg(bob))
cse303.line()

# Use up our upload quota:
cse303.do_cmd("Setting key k1 to 1K file.", "OK", client.kvI(alice, "k1", t1kname))
cse303.do_cmd("Setting key k2 to 1K file.", "OK", client.kvI(alice, "k2", t1kname))
cse303.do_cmd("Updating key k2 to 1K file.", "OKUPD", client.kvU(alice, "k2", t1kname))
cse303.do_cmd("Upserting key k3 to 1K file.", "OKINS", client.kvU(alice, "k3", t1kname))
cse303.do_cmd("Setting key k4 to 1K file.", "OK", client.kvI(alice, "k4", t1kname))
cse303.do_cmd("Setting key k5 to 1K file.", "OK", client.kvI(alice, "k5", t1kname))
cse303.do_cmd("Setting key k6 to 1K file.", "OK", client.kvI(alice, "k6", t1kname))
cse303.do_cmd("Setting key k7 to 1K file.", "OK", client.kvI(alice, "k7", t1kname))
cse303.line()

# Test for upload quota violations
cse303.do_cmd("Setting key k8 to 1K file.", "ERR_QUOTA_UP", client.kvI(alice, "k8", t1kname))
cse303.do_cmd("Updating key k9 to 1K file.", "ERR_QUOTA_UP", client.kvU(alice, "k9", t1kname))
cse303.do_cmd("Upserting key k7 to 1K file.", "ERR_QUOTA_UP", client.kvU(alice, "k7", t1kname))
cse303.line()

# Bob is still good
cse303.do_cmd("Upserting key k7 to 1K file.", "OKUPD", client.kvU(bob, "k7", t1kname))
cse303.line()

# Use up almost all of our download quota
cse303.do_cmd("Getting key k1.", "OK", client.kvG(alice, "k1"))
cse303.check_file_result(t1kname, "k1")
cse303.do_cmd("Getting all keys.", "OK", client.kvA(alice, allkeys))
cse303.check_file_list(allkeys, ["k1", "k2", "k3", "k4", "k5", "k6", "k7"])
cse303.do_cmd("Getting key k2.", "OK", client.kvG(alice, "k2"))
cse303.check_file_result(t1kname, "k2")
cse303.do_cmd("Getting key k3.", "OK", client.kvG(alice, "k3"))
cse303.check_file_result(t1kname, "k3")
cse303.do_cmd("Getting key k4.", "OK", client.kvG(alice, "k4"))
cse303.check_file_result(t1kname, "k4")
cse303.do_cmd("Getting key k5.", "OK", client.kvG(alice, "k5"))
cse303.check_file_result(t1kname, "k5")
cse303.do_cmd("Getting key k6.", "OK", client.kvG(alice, "k6"))
cse303.check_file_result(t1kname, "k6")
cse303.do_cmd("Getting key k7.", "OK", client.kvG(alice, "k7"))
cse303.check_file_result(t1kname, "k7")
cse303.line()

# Now let's see a violation, followed by a non-violation
cse303.do_cmd("Getting key k1.", "ERR_QUOTA_DOWN", client.kvG(alice, "k1"))
cse303.do_cmd("Getting all keys.", "OK", client.kvA(alice, allkeys))
cse303.check_file_list(allkeys, ["k1", "k2", "k3", "k4", "k5", "k6", "k7"])
cse303.line()

# Bob is still good
cse303.do_cmd("Getting key k7.", "OK", client.kvG(bob, "k7"))
cse303.check_file_result(t1kname, "k7")
cse303.line()

# Delete shouldn't cause quota violations, but this will be requests 22 and 23
cse303.do_cmd("Deleting key k6.", "OK", client.kvD(alice, "k6"))
cse303.do_cmd("Getting all keys.", "OK", client.kvA(alice, allkeys))
cse303.check_file_list(allkeys, ["k1", "k2", "k3", "k4", "k5", "k7"])
cse303.line()

# Top shouldn't quota yet
cse303.do_cmd("Getting top keys", "OK", client.kvT(alice, topkeys))
cse303.check_file_list_nosort(topkeys, ["k7", "k5", "k4"])
cse303.line()

# Now everything should give us request quota violations
cse303.do_cmd("Setting key k10 to 1K file.", "ERR_QUOTA_REQ", client.kvI(alice, "k10", t1kname))
cse303.do_cmd("Upserting key k2 to 1K file.", "ERR_QUOTA_REQ", client.kvU(alice, "k2", t1kname))
cse303.do_cmd("Updating key k3 to 1K file.", "ERR_QUOTA_REQ", client.kvU(alice, "k3", t1kname))
cse303.do_cmd("Getting key k1.", "ERR_QUOTA_REQ", client.kvG(alice, "k1"))
cse303.do_cmd("Getting all keys.", "ERR_QUOTA_REQ", client.kvA(alice, allkeys))
cse303.do_cmd("Deleting key k2.", "ERR_QUOTA_REQ", client.kvD(alice, "k2"))
cse303.do_cmd("Getting top keys", "ERR_QUOTA_REQ", client.kvT(alice, topkeys))
cse303.line()

# If we wait a bit, then we should be back to good
print("Waiting for " + server.qi + " seconds so that quotas can reset")
cse303.waitfor(int(server.qi) + 1) # one extra, to play it safe...
cse303.line()

cse303.do_cmd("Getting key k5.", "OK", client.kvG(alice, "k5"))
cse303.check_file_result(t1kname, "k5")
cse303.do_cmd("Getting key k7.", "OK", client.kvG(alice, "k7"))
cse303.check_file_result(t1kname, "k7")
cse303.do_cmd("Setting key k10 to 1K file.", "OK", client.kvI(alice, "k10", t1kname))
cse303.do_cmd("Getting all keys.", "OK", client.kvA(alice, allkeys))
cse303.check_file_list(allkeys, ["k1", "k2", "k3", "k4", "k5", "k7", "k10"])
cse303.do_cmd("Deleting key k5.", "OK", client.kvD(alice, "k5"))
cse303.do_cmd("Getting all keys.", "OK", client.kvA(alice, allkeys))
cse303.check_file_list(allkeys, ["k1", "k2", "k3", "k4", "k7", "k10"])
cse303.do_cmd("Getting top keys", "OK", client.kvT(alice, topkeys))
cse303.check_file_list_nosort(topkeys, ["k10", "k7", "k4"])
cse303.line()

# If we wait a bit, then we should be back to good
print("Waiting for " + server.qi + " seconds so that quotas can reset")
cse303.waitfor(int(server.qi) + 1) # one extra, to play it safe...
cse303.line()

# Now wipe out the download quota
cse303.do_cmd("Getting key k1.", "OK", client.kvG(alice, "k1"))
cse303.check_file_result(t1kname, "k1")
cse303.do_cmd("Getting key k2.", "OK", client.kvG(alice, "k2"))
cse303.check_file_result(t1kname, "k2")
cse303.do_cmd("Getting key k3.", "OK", client.kvG(alice, "k3"))
cse303.check_file_result(t1kname, "k3")
cse303.do_cmd("Getting key k4.", "OK", client.kvG(alice, "k4"))
cse303.check_file_result(t1kname, "k4")
cse303.do_cmd("Getting key k7.", "OK", client.kvG(alice, "k7"))
cse303.check_file_result(t1kname, "k7")
cse303.do_cmd("Getting key k10.", "OK", client.kvG(alice, "k10"))
cse303.check_file_result(t1kname, "k10")
cse303.do_cmd("Getting key k7.", "OK", client.kvG(alice, "k7"))
cse303.check_file_result(t1kname, "k7")
cse303.do_cmd("Getting key k1.", "OK", client.kvG(alice, "k1"))
cse303.check_file_result(t1kname, "k1")
cse303.line()

# KVA and KVT should fail
cse303.do_cmd("Getting all keys.", "ERR_QUOTA_DOWN", client.kvA(alice, allkeys))
cse303.do_cmd("Getting top keys", "ERR_QUOTA_DOWN", client.kvT(alice, topkeys))
cse303.line()

# If we wait a bit, then we should be back to good
print("Waiting for " + server.qi + " seconds so that quotas can reset")
cse303.waitfor(int(server.qi) + 1) # one extra, to play it safe...
cse303.line()
cse303.do_cmd("Getting top keys", "OK", client.kvT(alice, topkeys))
cse303.check_file_list_nosort(topkeys, ["k1", "k7", "k10", "k4"])
cse303.line()

# Clean up
cse303.do_cmd("Stopping server.", "OK", client.bye(alice))
cse303.await_server("Waiting for server to shut down.", "Server terminated", server.pid)
cse303.line()
cse303.clean_common_files(server, client)
cse303.delfile(t1kname)