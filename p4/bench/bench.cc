#include <atomic>
#include <chrono>
#include <iostream>
#include <libgen.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "../common/hashtable.h"

using namespace std;

/// arg_t is used to store the command-line arguments of the program
struct server_arg_t {
  /// The key range (e.g., 65536 for a range of 1..65535)
  size_t keys = 1024;

  /// The number of threads
  size_t threads = 1;

  /// The read-only ratio.  (100-reads)/2 will be the insert *and* remove ratio
  size_t reads = 80;

  /// The iterations per thread
  size_t iters = 1048576;

  /// Display a usage message?
  bool usage = false;

  /// Number of buckets for the server's hash tables
  size_t buckets = 1024;
};

/// Parse the command-line arguments, and use them to populate the provided args
/// object.
///
/// @param argc The number of command-line arguments passed to the program
/// @param argv The list of command-line arguments
/// @param args The struct into which the parsed args should go
void parse_args(int argc, char **argv, server_arg_t &args) {
  long opt;
  while ((opt = getopt(argc, argv, "k:t:r:i:b:h")) != -1) {
    switch (opt) {
    case 'k':
      args.keys = atoi(optarg);
      break;
    case 't':
      args.threads = atoi(optarg);
      break;
    case 'r':
      args.reads = atoi(optarg);
      break;
    case 'i':
      args.iters = atoi(optarg);
      break;
    case 'b':
      args.buckets = atoi(optarg);
      break;
    case 'h':
      args.usage = true;
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
  cout << basename(progname) << ": Hash Table (Integer Set) Benchmark\n"
       << "  -k [int] Key range\n"
       << "  -t [int] Threads\n"
       << "  -r [int] Read-only percent\n"
       << "  -i [int] Iterations per thread\n"
       << "  -b [int] Number of buckets\n"
       << "  -h       Print help (this message)\n";
}

/// An enum for the 6 events that can happen in an intset benchmark
enum EVENTS {
  INS_T = 0,
  INS_F = 1,
  RMV_T = 2,
  RMV_F = 3,
  LOK_T = 4,
  LOK_F = 5,
  COUNT = 6
};

int main(int argc, char **argv) {
  // Parse the command-line arguments
  server_arg_t args;
  parse_args(argc, argv, args);
  if (args.usage) {
    usage(argv[0]);
    return 0;
  }

  // Print configuration
  cout << "# (k,t,r,i,b) = (" << args.keys << "," << args.threads << ","
       << args.reads << "," << args.iters << "," << args.buckets << ")\n";

  // Make a hash table, populate it with 50% of the keys.  We ignore values
  ConcurrentHashTable<int, int> tbl(args.buckets);
  for (size_t i = 0; i < args.keys; i += 2) {
    tbl.insert(i, 0, []() {});
  }

  // These vars are needed by the threads:
  chrono::high_resolution_clock::time_point start_time, end_time;
  atomic<size_t> barrier_1(0), barrier_2(0), barrier_3(0);
  atomic<uint64_t> stats[EVENTS::COUNT];
  for (auto i = 0; i < EVENTS::COUNT; ++i)
    stats[i] = 0;

  // launch a bunch of threads, wait for them to finish
  vector<thread> threads;
  for (size_t i = 0; i < args.threads; ++i) {
    threads.push_back(thread(
        [&](int tid) {
          // stats counter
          uint64_t my_stats[EVENTS::COUNT] = {0};
          // Announce that this thread has started, wait for all to start
          ++barrier_1;
          while (barrier_1 != args.threads) {
            // spin wait
          }
          // All threads are started.  Thread 0 reads clock, all wait
          if (tid == 0)
            start_time = chrono::high_resolution_clock::now();
          ++barrier_2;
          while (barrier_2 != args.threads) {
            // spin
          }

          // Run the test
          unsigned seed = tid;
          for (size_t o = 0; o < args.iters; ++o) {
            size_t action = rand_r(&seed) % 100;
            size_t key = rand_r(&seed) % args.keys;
            if (action < args.reads) {
              if (tbl.do_with_readonly(key, [](int) {}))
                ++my_stats[EVENTS::LOK_T];
              else
                ++my_stats[EVENTS::LOK_F];
            } else if (action < args.reads + (100 - args.reads) / 2) {
              if (tbl.insert(key, 0, []() {}))
                ++my_stats[EVENTS::INS_T];
              else
                ++my_stats[EVENTS::INS_F];
            } else {
              if (tbl.remove(key, []() {}))
                ++my_stats[EVENTS::RMV_T];
              else
                ++my_stats[EVENTS::RMV_F];
            }
          }
          ++barrier_3;
          while (barrier_3 != args.threads) {
            // spin
          }
          if (tid == 0)
            end_time = chrono::high_resolution_clock::now();

          // Update counts
          for (auto i = 0; i < EVENTS::COUNT; ++i)
            stats[i] += my_stats[i];
        },
        i));
  }
  for (size_t i = 0; i < args.threads; ++i) {
    threads[i].join();
  }

  auto dur =
      chrono::duration_cast<chrono::duration<double>>(end_time - start_time)
          .count();
  uint64_t ops = 0;
  for (auto i = 0; i < EVENTS::COUNT; ++i)
    ops += stats[i];
  cout << "Throughput (ops/sec): " << ops / dur << endl;
  cout << "Execution Time (sec): " << dur << endl;
  cout << "Total Operations:     " << ops << endl;
  cout << "  Lookup (True) :     " << stats[EVENTS::LOK_T] << endl;
  cout << "  Lookup (False):     " << stats[EVENTS::LOK_F] << endl;
  cout << "  Insert (True) :     " << stats[EVENTS::INS_T] << endl;
  cout << "  Insert (False):     " << stats[EVENTS::INS_F] << endl;
  cout << "  Remove (True) :     " << stats[EVENTS::RMV_T] << endl;
  cout << "  Remove (False):     " << stats[EVENTS::RMV_F] << endl;
}
