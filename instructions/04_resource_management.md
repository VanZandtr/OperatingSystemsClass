# Assignment #4: Enforcing Quotas and Managing Resources

The purpose of this assignment is to implement some standard resource management
concepts: quotas and most-recently-used (MRU) tracking.  (Remember: MRU and LRU
are equivalent in complexity!)

## Assignment Details

Once we have an on-line service, one of the things we must be careful about is
how to ensure that it is not abused.  There are quite a few challenges in doing
so... what is a "fair" amount of use?  Should it vary by class of user?  How
strictly should a rule be enforced?  How much does enforcing rules cost?  And
for that matter, are some rules simply unenforceable?

We will make four additions to the service in this assignment.  The first is to
add a `KVT` (TOP) command to the client and server.  `KVT` is like `KVA` from
assignment #2, except that the server will have a configurable threshold `T`,
and track the `T` most recently accessed keys.  `KVT` will return as many of
these keys as have not been deleted.  In this manner, supporting `KVT` will be
akin to maintaining an LRU cache of the hottest keys in the key/value store.  A
practical system might use such a cache to accelerate lookups (now you know why
YouTube advertisements load so much more quickly than the videos that follow!).
So, supposing that `G5` means "get key 5" and `R9` means "remove key 9", then if
`T` is 4 and we have the sequence `G6 G4 G5 G7 G6 R5`, then `KVT` should return
`6\n7\n4`.  That is, the second `G6` moves `6` *all the way to the front*, and
the presence of `R5` means that we will will only have data for 3 elements, even
though `T` is 4.

Our other three extensions will track the times of recent requests.  We will
enforce three quotas: download bandwidth, upload bandwidth, and number of
requests.  For download bandwidth, if a *user* requests more data (via `KVG`,
`KVA`, and `KVT`) in a time interval than the threshold allows, then
*subsequent* `KVG`, `KVA`, and `KVT` commands within the interval will result in
ERR_QUOTA_DOWN.  Similarly, both `KVU` and `KVI` will have their payloads
charged against an upload quota, and exceeding the quota will result in
ERR_QUOTA_UP.  Finally, every `KV?` operation will be counted against a user's
request-per-interval quota, and if the request rate exceeds the quota,
ERR_QUOTA_REQ will be returned.

Note that you will need to make sure that your management of quota information
is thread-safe, so that simultaneous requests from the same user cannot trick
your server.  Also, we will not persist quota information: restarting the server
resets all quotas.

## Getting Started

Your git repository has a new folder, `p4`, which includes binary files that
represent the solution to assignment 3.  The Makefile has been updated so that
you do not need to have completed the first three assignments in order to get
full credit for this assignment.

There is a test script called `scripts/p4.py`, which you can use to test your
code.  These tests will help you to understand the expected behavior of the
server.

The new commands and API extensions have been added to `protocol.h`.  Note that
there are new possible errors for commands from Assignment #2.

## Tips and Reminders

Once you have one quota working, the others are likely to be pretty easy... so
the fastest way to getting a lot of points on this assignment is to create a
good data structure for managing quotas.

Ensuring that your management of quotas is thread safe is not easy.  You will
probably find that you need to chain together lambdas to get it to work.

As in the last assignment, you should keep in mind that subsequent assignments
will build upon this... so as you craft a solution, be sure to think about how
to make it maintainable.

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
atomicity.  As before, we reserve the right to deduct "style" points if your
code is especially convoluted.  Please be sure to use your tools well.  For
example, Visual Studio Code (and emacs, and vim) have features that auto-format
your code.  You should use these features.

There are three main gradeable portions of the assignment:

* Do KVT queries (top queries) track results correctly?
* Are the three quotas managed properly?
* Is threading handled correctly?

## Notes About the Reference Solution

You will need to make edits to three files in order to solve this assignment:
`server_storage.cc`, `mru.cc`, and `quota_tracker.cc`.

The reference solution to `mru.cc` is 91 lines.  It uses a `std::deque` as its
main data structure for tracking the most recently used elements.  Technically,
it is possible to use a `std::vector`, but even for the `O(N)` algorithms that
we can use for this assignment, a vector would be slower.  You should be sure
you understand why (it has to do with erasing data).  Also, note that for very
large MRU caches, a `std::deque` would probably not have satisfactory asymptotic
performance.

The `quota_tracker.cc` reference solution is similarly short, consisting of 84
lines of code.  The solution uses the C/Unix `time` function to get the system
time, and stores it in a `time_t` object.  If you would rather use something
from `std::chrono`, that is fine.  Quota_tracker needs to maintain a list of
time/quantity pairs, in order to know when a quota has actually been exceeded.
A `std::deque` is a good choice for this data structure, for the same reasons
that it is good for `mru.cc`.  In fact, `std::deque` might even be the optimal
data structure choice for the quota tracker.

You will find, unfortunately, that the most natural ways to use a quota_tracker
are going to require you to implement a copy constructor.  The shell of that
constructor is provided, but its implementation will depend on your code, so it
is not provided.  Note that the copy constructor is not complicated in terms of
lines of code, but you do need to understand why a copy constructor is needed,
and what it ought to do.

The reference solution adds 187 lines of code to `server_storage.cc`.  If you
think carefully about how quotas need to be checked, you will probably find that
most of this code is copy-and-paste.  It is possible to solve the assignment in
fewer lines.  When you work on this, please remember that all of the "kv" tasks
need at least one quota check, and some need two.

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

You should be done with this assignment before 11:59 PM on 22 Nov 2019.  Please
be sure to `git commit` and `git push` before that time, so that we can promptly
collect and grade your work.
