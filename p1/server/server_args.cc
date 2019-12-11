#include <iostream>
#include <libgen.h>
#include <unistd.h>

#include "server_args.h"

using namespace std;

/// Parse the command-line arguments, and use them to populate the provided args
/// object.
///
/// @param argc The number of command-line arguments passed to the program
/// @param argv The list of command-line arguments
/// @param args The struct into which the parsed args should go
void parse_args(int argc, char **argv, server_arg_t &args) {
  long opt;
  while ((opt = getopt(argc, argv, "p:f:k:ht:b:i:u:d:r:o:a:")) != -1) {
    switch (opt) {
    case 'p':
      args.port = atoi(optarg);
      break;
    case 'f':
      args.datafile = string(optarg);
      break;
    case 'k':
      args.keyfile = string(optarg);
      break;
    case 'h':
      args.usage = true;
      break;
    case 't':
    case 'b':
    case 'i':
    case 'u':
    case 'd':
    case 'r':
    case 'o':
    case 'a':
      break;
    default:
      args.usage = true;
      return;
    }
  }
}

/// Display a help message to explain how the command-line parameters for this
/// program work
///
/// @progname The name of the program
void usage(char *progname) {
  cout << basename(progname) << ": company user directory server\n"
       << "  -p [int]    Port on which to listen for incoming connections\n"
       << "  -f [string] File for storing all data\n"
       << "  -k [string] Basename of file for storing the server's RSA keys\n"
       << "  -t [int]    Ignored\n"
       << "  -b [int]    Ignored\n"
       << "  -i [int]    Ignored\n"
       << "  -u [int]    Ignored\n"
       << "  -d [int]    Ignored\n"
       << "  -r [int]    Ignored\n"
       << "  -o [int]    Ignored\n"
       << "  -a [string] Ignored\n"
       << "  -h          Print help (this message)\n";
}
