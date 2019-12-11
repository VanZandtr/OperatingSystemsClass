#pragma once

#include <string>

/// arg_t is used to store the command-line arguments of the program
struct server_arg_t {
  /// The port on which to listen
  int port;

  /// The file for storing all data
  std::string datafile;

  /// The file holding the AES key
  std::string keyfile;

  /// Display a usage message?
  bool usage = false;

  /// Number of threads for the server to use (unused for now)
  int threads = 1;

  /// Number of buckets for the server's hash tables
  size_t num_buckets = 1024;

  /// Time interval over which a quota is enforced
  size_t quota_interval = 60;

  /// Quota for uploads against the K/V store, in bytes per minute
  size_t quota_up = 1048576;

  /// Quota for downloads against the K/V store, in bytes per minute
  size_t quota_down = 1048576;

  /// Quota for requests per minute against the K/V store
  size_t quota_req = 16;

  /// Number of keys to track for TOP queries
  size_t top_size = 4;
};

/// Parse the command-line arguments, and use them to populate the provided args
/// object.
///
/// @param argc The number of command-line arguments passed to the program
/// @param argv The list of command-line arguments
/// @param args The struct into which the parsed args should go
void parse_args(int argc, char **argv, server_arg_t &args);

/// Display a help message to explain how the command-line parameters for this
/// program work
///
/// @progname The name of the program
void usage(char *progname);
