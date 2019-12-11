# Assignment #5: A Virtual Execution Environment

In this assignment, we will gain a deeper appreciation for the power of
virtualization.  We will do so in two ways.  First, we will transform our
key/value store into a server that provides a new virtual feature: map/reduce
functionality.  Second, we will heavily use the process abstraction to keep our
server secure while we add this new feature.

## Assignment Details

In Java, it is possible to use *dynamic class loading* to load `.class` files
into a running program.  If the loaded class implements an `interface` that the
program already understands, it can use the new class anywhere that the old
interface was used.

In C++, we can do something very similar: we can compile a `.cc` file to a
*shared object*, and then load it into our program.  When we load it, we can
pick out functions within the shared object and use them.  Shared objects (or
"DLLs", in Windows) are incredibly powerful for a number of reasons that you
should understand.  The use of shared objects in this assignment is not the most
common, but it is very powerful.

To leverage this feature, we will add an *administrator* concept to our server.
The administrator's user name will be given on the command line.  The
administrator will have a new command that only it can execute from the client:
`KVF`, which registers functions.  Note that you will still need to *register*
an administrator account... it will not be created automatically, despite the
command-line argument.

To use KVF, the administrator needs a `.so` with two functions: `map()` and
`reduce()`.  Any user can use a `KMR` command to request that these functions be
used.

To use the functions, the server will do something similar to a `KVA`: it will
iterate through all the key/value pairs, using 2pl.  For each pair, it will call
the `map()` function, and append the result to a temporary `vector`.  Once all
the pairs have been visited, then the server will pass the temporary vector to
the `reduce()` function.  The final result will be sent back to the user.

Your server will need to maintain a `std::map` to hold the registered functions.
It should use a `std::shared_mutex` (a readers/writer lock), so that multiple
threads can get functions from the map simultaneously, but only one thread can
insert new functions.

We have one final requirement: running user-provided code inside the server
process is dangerous.  We don't want to simply trust the administrator to only
load safe code.  Instead, the server should `fork()` a child process and use
`pipe()` to create channels for communicating with the child.  The parent will
iterate through keys, and will send them to the child.  The child will execute
the `map()` and `reduce()` functions.  The child will then write the result back
on a pipe, so that a server thread can send the result to the client.

## Getting Started

Your git repository has a new folder, `p5`, which includes binary files that
represent the solution to assignment 4.  The Makefile has been updated so that
you do not need to have completed the first four assignments in order to get
full credit for this assignment.  The Makefile also now can build some .so
files, for testing.

There is a test script called `scripts/p5.py`, which you can use to test your
code.  Reading these tests will help you to understand the expected behavior of
the server.

The new commands and API extensions have been added to `protocol.h`.

You will need to understand many concepts to do well on this assignment.  You
will need to start early.  Some features, like using a `std::map`, are not very
hard.  Some features, like using `fork()`, are difficult.  However, you can make
a functional but insecure server by calling the `map()` and `reduce()` functions
from the main server process.  This will help when debugging your interaction
with .so files.

## Tips and Reminders

When you call `fork()` from a multithreaded process, the new child process will
only have one thread: a clone of the thread who called `fork()`.  There are no
guarantees about the state of any locks in the child process.  Therefore, it is
essential that you do not have the child access the key/value store: it could
wait forever.

If you `dlclose()` a .so, its functions are no longer available.  You will need
to keep open any .so that you have loaded, and only close them at shutdown time.

When calling `dlopen()`, you cannot re-use file names, even after deleting the
files.  You also cannot load a .so from a `std::vector`... you must use a
temporary file.  You should think carefully about how to make unique file names
to pass to `dlopen()`.

You do not need to enforce quotas on the `KMR` and `KVF` functions.

**Start Early**.  Just reading the code and understanding what is happening
takes time.  If you start reading the assignment early, you'll give yourself
time to think about what is supposed to be happening, and that will help you to
figure out what you will need to do.

As always, please be careful about not committing unnecessary files into your
repository.

Your programs should never require keyboard input. In particular, the client
should get all its parameters from the command line, and usually it rely on
files for getting and storing data.

Your server should **not** store plain-text passwords in the file.

## Grading

If the script passes, then you will receive full "functionality" points.  We
will manually inspect your code to determine if it is correct with regard to
atomicity and forking.  As before, we reserve the right to deduct "style" points
if your code is especially convoluted.  Please be sure to use your tools well.
For example, Visual Studio Code (and emacs, and vim) have features that
auto-format your code.  You should use these features.

There are four main gradeable portions of the assignment:

* Do .so files load correctly on the server?
* Can clients invoke functions on the server?
* Are map() and reduce() running in a child process?
* Is the program correct with regard to concurrency?

## Notes About the Reference Solution

In this assignment, we have split the `server_storage` files into two parts. The
part with all of the functionality from the previous assignments can be found in
`server_storage.h` and `server_storage.cc`.  However, the implementation of the
internal class for the `Storage` object is now in a new file, called
`server_storage_internal.h`.  By doing this, you do not need to re-write any of
`server_storage.cc`... you just need to implement the new features.  You can do
this in `server_storage_ex.cc`.

The code in the reference solution for `server_storage_ex.cc` is about 216
lines.  There are three functions.  `register_mr` is the easiest: it just
authenticates the administrator, and then passes the given `vec` to the `funcs`
table.  It is only 7 lines of code.  `invoke_mr` is much more complex, because
it needs to `fork()` and `waitpid()`, manage `pipe()` objects, run a
`do_all_readonly()`, and interact with a child process by reading and writing
via pipes.  The reference solution is about 120 lines of code, including all of
the error handling.  This code also makes use of a helper function, which is run
by the child process.  The helper is the code that actually runs the functions
on the data that is extracted from the k/v store.  It is about 40 lines.

You will also need to implement `func_table.cc`.  Interacting with .so files may
be new to you.  If so, you may find steps 1 and 2 of this (very old) tutorial
useful: `http://www.cse.lehigh.edu/~spear/cse398/tutorials/extensions.html`.
Note that every valid .so will have a function called `map()` and a function
called `reduce()`.  Also, note that the .cc files that produce the .so files
must avoid C++ name mangling, through the use of `extern "C" {}`.  While you do
not need to write any new shared objects, it is good to understand the code that
we provide.

The design of the `func_table` object is not completely specified for you.  You
will need to think about what fields the `Internal` object requires, and you
will need a strategy for having unique names.  The reference solution is 146
lines of code, including the `Internal` object.

## Collaboration and Getting Help

You may work in teams of 2 for this assignment.  If you wish to have a different
team than in the last assignment, please contact the professor immediately.

If you are working in a team, you should **pair program** for the entire
assignment.  The requirements are such that it's not really feasible for
students to work on separate parts at the same time.

If you require help, then **for this assignment**, you may seek it from any
of the following sources:

* The professor and TAs, via office hours or Piazza
* The Internet, as long as you use the Internet as a read-only resource and do
  not post requests for help to online sites.

If you are familiar with `man` pages, please note that the easiest way to find a
man page is via Google.  For example, typing `man printf` will probably return
`https://linux.die.net/man/3/printf` as one of the first links.  It is fine to
use Google to find man pages.

StackOverflow is a wonderful tool for professional software engineers.  It is a
horrible place to ask for help as a student.  You should feel free to use
StackOverflow, but only as a *read only* resource.  In this class, you should
**never** need to ask a question on StackOverflow.

## Deadline

You should be done with this assignment before 11:59 PM on 13 Dec 2019. Please
be sure to `git commit` and `git push` before that time, so that we can promptly
collect and grade your work.
