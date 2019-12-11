#pragma once

#include <memory>
#include <string>
#include <utility>

#include "../common/functypes.h"
#include "../common/vec.h"

/// func_table is a table that stores functions that have been registered with
/// our server, so that they can be invoked by clients on the key/value pairs in
/// kv_store.
class func_table {
  /// Internal is the class that stores all the members of a func_table object.
  /// To avoid pulling too much into the .h file, we are using the PIMPL pattern
  /// (https://www.geeksforgeeks.org/pimpl-idiom-in-c-with-examples/)
  struct Internal;

  /// A reference to the internal fields of the Storage object
  std::unique_ptr<Internal> fields;

public:
  /// Construct a function table for storing registered functions
  func_table();

  /// Destruct a function table
  ~func_table();

  /// Register the map() and reduce() functions from the provided .so, and
  /// associate them with the provided name.
  ///
  /// @param mrname The name to associate with the functions
  /// @param so     The so contents from which to find the functions
  ///
  /// @returns a vec with a status message
  vec register_mr(const std::string &mrname, const vec &so);

  /// Get the (already-registered) map() and reduce() functions asssociated with
  /// a name.
  ///
  /// @param name The name with which the functions were mapped
  ///
  /// @returns A pair of function pointers, or {nullptr, nullptr} on error
  std::pair<map_func, reduce_func> get_mr(const std::string &mrname);

  /// When the function table shuts down, we need to de-register all the .so
  /// files that were loaded.
  void shutdown();
};