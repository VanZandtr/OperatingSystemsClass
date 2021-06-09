# CSE 303 Individual Student Repository

## Assignment Details

In CSE303: Operating Systems, our goal is to learn as much as possible about the
five core concepts in Operating Systems:

* Concurrency
* Persistence
* Resource Management
* Security
* Virtualization

In CSE303, we will learn about these five topics through both *theory* and
*practice*.  For the *theory* portion of our learning, we will read a textbook,
have robust conversations in class, and demonstrate the depth of our knowledge
via quizzes and exams.  For the *practice* portion of our learning, we will
write code in C/C++ that runs at a sufficiently low level that it enables us to
get hands-on experience with how these five topics manifest in real-world
systems.

However, before we can have sophisticated interactions with our computer
systems, we need to be sure that we have a baseline understanding of how to
write correct low-level code.  To that end, in this assignment we will write a
handful of simple programs.  All of the guidance for writing these programs is
available online, in the tutorials at
http://www.cse.lehigh.edu/~spear/cse303_tutorials/.

These tutorials cover six important concepts:

* **Virtualization**: You will set up a Docker container for doing all of your
  development.  By using Docker, you will be guaranteed to have exactly the same
  development environment as the professor and TAs, so that you can be sure that
  when code works on your machine, it will work on ours.  This will also ensure
  that when code doesn't work on your machine, we will be able to reproduce the
  bug on our machine, so that we can help you figure out what's wrong.

* Basic C Programming: You will write code that does I/O to **persistent** files,
  and uses the standard C library.  You will also use some standard tools, like
  `make` and `git`.

* Transition to C++: You will start writing code that uses powerful features of
  C++, such as `lambdas`.  These features make it easier to write correct code,
  maintainable, and extensible code.  Remember: low-level systems code can last
  for a decade or longer... maintainability is important!

* Networking and **Resource Management**: You will create a several
  client/server programs, and learn how to use the Unix `screen` tool to
  multiplex your terminal.  You will also learn how to use the `select` system
  call to allow a single thread to serve multiple clients simultaneously and
  efficiently.

* **Concurrency**: You will learn how to use some of C++'s concurrency features,
  such as `threads`, `mutexes`, and `atomic` variables, to write a program that
  is capable of using multiple CPU cores, and communicating correctly among
  them.

* Encryption: You will use open-source libraries to encrypt data using the `RSA`
  and `AES` algorithms.  Through encryption, you will be able to **securely**
  store data, in a manner that cannot be compromised by an attacker.  (But
  remember: security is much more than just encryption!)



