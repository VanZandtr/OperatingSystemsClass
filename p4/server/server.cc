#include <iostream>
#include <openssl/rsa.h>
#include <sys/stat.h>
#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/file.h"
#include "../common/net.h"
#include "server_args.h"
#include "server_parsing.h"
#include "server_storage.h"
int test_diff(int argc, char **argv);

using namespace std;

int main(int argc, char **argv) {
  // Parse the command-line arguments
  server_arg_t args;
  parse_args(argc, argv, args);
  if (args.usage) {
    usage(argv[0]);
    return 0;
  }

  // print the configuration
  cout << "Listening on port " << args.port << " using (key/data) = ("
       << args.keyfile << ", " << args.datafile << ")\n";

  // If the key files don't exist, create them and then load the private key.
  RSA *pri = init_RSA(args.keyfile);
  if (pri == nullptr) {
    return -1;
  }
  ContextManager r([&]() { RSA_free(pri); });

  // load the public key file contents
  auto pub = load_entire_file(args.keyfile + ".pub");
  if (pub.size() == 0) {
    return -1;
  }

  // If the data file exists, load the data into a Storage object.  Otherwise,
  // create an empty Storage object.
  Storage storage(args.datafile, args.num_buckets, args.quota_up,
                  args.quota_down, args.quota_req, args.quota_interval,
                  args.top_size);
  if (!storage.load()) {
    return 0;
  }

  // Start listening for connections.
  int sd = create_server_socket(args.port);
  ContextManager csd([&]() { close(sd); });
  // Create a thread pool that will invoke serve_client (from a pool thread)
  // each time a new socket is given to it.
  thread_pool pool(args.threads,
                   [&](int sd) { return serve_client(sd, pri, pub, storage); });

  // Start accepting connections and passing them to the pool.
  accept_client(sd, pool);

  // The program can't exit until all threads in the pool are done.
  pool.await_shutdown();

  // Now that all threads are done, we can shut down the Storage
  storage.shutdown();

  // When accept_client returns, it means we received a BYE command, so let csd
  // run...
  cerr << "Server terminated\n";
}

