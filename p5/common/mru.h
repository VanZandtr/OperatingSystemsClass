#pragma once

#include <memory>
#include <string>

/// mru_manager provides a mechanism for managing a listing of the K most recent
/// elements that have been given to it.  It can be used to produce a "top"
/// listing of the most recently accessed keys.
class mru_manager {
  /// Internal is the class that stores all the members of a mru_manager object.
  /// To avoid pulling too much into the .h file, we are using the PIMPL pattern
  /// (https://www.geeksforgeeks.org/pimpl-idiom-in-c-with-examples/)
  struct Internal;

  /// A reference to the internal fields of the mru_manager object
  std::unique_ptr<Internal> fields;

public:
  /// Construct the mru_manager by specifying how many things it should track
  mru_manager(size_t elements);

  /// Destruct the mru_manager
  ~mru_manager();

  /// Insert an element into the mru_manager, making sure that (a) there are no
  /// duplicates, and (b) the manager holds no more than /max_size/ elements.
  ///
  /// @param elt The element to insert
  void insert(const std::string &elt);

  /// Remove an instance of an element from the mru_manager.  This can leave the
  /// manager in a state where it has fewer than max_size elements in it.
  ///
  /// @param elt The element to remove
  void remove(const std::string &elt);

  /// Clear the mru_manager
  void clear();

  /// Produce a concatenation of the top entries, in order of popularity
  ///
  /// @returns A newline-separated list of values
  std::string get();
};