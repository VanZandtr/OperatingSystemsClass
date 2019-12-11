#include <iostream>
#include <libgen.h>
#include <unistd.h>

#include "client_args.h"

using namespace std;

/// Parse the command-line arguments, and use them to populate the provided args
/// object.
///
/// @param argc The number of command-line arguments passed to the program
/// @param argv The list of command-line arguments
/// @param args The struct into which the parsed args should go
void parse_args(int argc, char **argv, client_arg_t &args) {
  long opt;
  while ((opt = getopt(argc, argv, "k:u:w:s:p:C:1:2:h")) != -1) {
    switch (opt) {
    case 'p': // port of server
      args.port = atoi(optarg);
      break;
    case 's': // hostname of server
      args.server = string(optarg);
      break;
    case 'k': // name of keyfile
      args.keyfile = string(optarg);
      break;
    case 'u': // username
      args.username = string(optarg);
      break;
    case 'w': // password
      args.userpass = string(optarg);
      break;
    case 'C': // command
      args.usage |= args.command != "";
      args.command = string(optarg);
      break;
    case '1': // first argument
      args.usage |= args.arg1 != "";
      args.arg1 = string(optarg);
      break;
    case '2': // second argument
      args.usage |= args.arg2 != "";
      args.arg2 = string(optarg);
      break;
    case 'h': // help message
      args.usage = true;
      break;
    default:
      args.usage = true;
      return;
    }
  }
  // Validate command formats
  string arg0[] = {"BYE", "SAV", "REG"};
  string arg1[] = {"SET", "GET", "ALL"};
  bool found = false;
  for (auto a : arg0) {
    if (args.command == a) {
      found = true;
      args.usage |= (args.arg1 != "" || args.arg2 != "");
    }
  }
  for (auto a : arg1) {
    if (args.command == a) {
      found = true;
      args.usage |= (args.arg1 == "" || args.arg2 != "");
    }
  }
  args.usage |= !found;
}

/// Display a help message to explain how the command-line parameters for this
/// program work
///
/// @progname The name of the program
void usage(char *progname) {
  cout << basename(progname) << ": company user directory client\n"
       << " Required Configuration Parameters:\n"
       << "  -k [file]   The filename for storing the server's public key\n"
       << "  -u [string] The username to use for authentication\n"
       << "  -w [string] The password to use for authentication\n"
       << "  -s [string] IP address or hostname of server\n"
       << "  -p [int]    Port to use to connect to server\n"
       << "  -C [string] The command to execute (choose one from below)\n"
       << " Admin Commands (pass via -C):\n"
       << "  BYE             Force the server to stop\n"
       << "  SAV             Instruct the server to save its data\n"
       << " Auth Table Commands (pass via -C, with argument as -1)\n"
       << "  REG             Register a new user\n"
       << "  SET -1 [file]   Set user's data to the contents of the file\n"
       << "  GET -1 [string] Get data for the provided user\n"
       << "  ALL -1 [file]   Get list of all users' names, and save to a file\n"
       << " Other Options:\n"
       << "  -1          Provide first argument to a command\n"
       << "  -2          Provide second argument to a command\n"
       << "  -h          Print help (this message)\n";
}
