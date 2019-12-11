#pragma once

#include <string>

/// client_arg_t is used to store the command-line arguments of the client
struct client_arg_t {
  /// The port on which to listen
  int port = 0;

  /// The IP or hostname of the server
  std::string server = "";

  /// The file for storing the server's public key
  std::string keyfile = "";

  /// The user's name
  std::string username = "";

  /// The user's password
  std::string userpass = "";

  /// The command to execute
  std::string command = "";

  /// The first argument to the command (if any)
  std::string arg1 = "";

  /// The second argument to the command (if any)
  std::string arg2 = "";

  /// Display a usage message?
  bool usage = false;
};

/// Parse the command-line arguments, and use them to populate the provided args
/// object.
///
/// @param argc The number of command-line arguments passed to the program
/// @param argv The list of command-line arguments
/// @param args The struct into which the parsed args should go
void parse_args(int argc, char **argv, client_arg_t &args);

/// Display a help message to explain how the command-line parameters for this
/// program work
///
/// @progname The name of the program
void usage(char *progname);
