#pragma once

#include <memory>
#include <string>
#include <utility>

#include "../common/vec.h"

/// Storage is the main data type managed by the server.  For the time being, it
/// wraps a std::unordered_map that serves as an authentication table.  The
/// authentication table holds user names and hashed passwords, as well as a
/// single content object per user.
///
/// The public interface of Storage provides functions that correspond 1:1 with
/// the data requests that a client can make.  In that manner, the server
/// command handlers need only parse a request, send its parts to the Storage
/// object, and then format and return the result.
///
/// Storage is a persistent object.  For the time being, persistence is
/// achieved by writing the entire object to disk in response to SAV
/// messages. We use a relatively simple binary wire format:
///
///  - Each autnetication table entry begins with the magic 8-byte constant
///    AUTHAUTH
///  - Next comes a 4-byte binary write of the length of the username
///  - Then a binary write of the bytes of the username
///  - Then a binary write of the length of pass_hash
///  - Then a binary write of the bytes of pass_hash
///  - Then a binary write of num_bytes
///  - Finally, if num_bytes > 0, a binary write of the bytes field
///
/// This is repeated for each entry in the Auth table.
class Storage {
  /// Internal is the class that stores all the members of a Storage object.  To
  /// avoid pulling too much into the .h file, we are using the PIMPL pattern
  /// (https://www.geeksforgeeks.org/pimpl-idiom-in-c-with-examples/)
  struct Internal;

  /// A reference to the internal fields of the Storage object
  std::unique_ptr<Internal> fields;

public:
  /// Construct an empty object and specify the file from which it should be
  /// loaded.  To avoid exceptions and errors in the constructor, the act of
  /// loading data is separate from construction.
  Storage(const std::string &fname);

  /// Destructor for the storage object.
  ~Storage();

  /// Populate the Storage object by loading an auth_table from this.filename.
  /// Note that load() begins by clearing the auth_table, so that when the call
  /// is complete, exactly and only the contents of the file are in the
  /// auth_table.
  ///
  /// @returns false if any error is encountered in the file, and true
  ///          otherwise.  Note that a non-existent file is not an error.
  bool load();

  /// Create a new entry in the Auth table.  If the user_name already exists, we
  /// should return an error.  Otherwise, hash the password, and then save an
  /// entry with the username, hashed password, and a zero-byte content.
  ///
  /// @param user_name The user name to register
  /// @param pass      The password to associate with that user name
  ///
  /// @returns False if the username already exists, true otherwise
  bool add_user(const std::string &user_name, const std::string &pass);

  /// Set the data bytes for a user, but do so if and only if the password
  /// matches
  ///
  /// @param user_name The name of the user whose content is being set
  /// @param pass      The password for the user, used to authenticate
  /// @param content   The data to set for this user
  ///
  /// @returns A pair with a bool to indicate error, and a vector indicating the
  ///          message (possibly an error message) that is the result of the
  ///          attempt
  vec set_user_data(const std::string &user_name, const std::string &pass,
                    const vec &content);

  /// Return a copy of the user data for a user, but do so only if the password
  /// matches
  ///
  /// @param user_name The name of the user who made the request
  /// @param pass      The password for the user, used to authenticate
  /// @param who       The name of the user whose content is being fetched
  ///
  /// @returns A pair with a bool to indicate error, and a vector indicating the
  ///          data (possibly an error message) that is the result of the
  ///          attempt.  Note that "no data" is an error
  std::pair<bool, vec> get_user_data(const std::string &user_name,
                                     const std::string &pass,
                                     const std::string &who);

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user_name The name of the user who made the request
  /// @param pass      The password for the user, used to authenticate
  ///
  /// @returns A vector with the data, or a vector with an error message
  std::pair<bool, vec> get_all_users(const std::string &user_name,
                                     const std::string &pass);

  /// Authenticate a user
  ///
  /// @param user_name The name of the user who made the request
  /// @param pass      The password for the user, used to authenticate
  ///
  /// @returns True if the user and password are valid, false otherwise
  bool auth(const std::string &user_name, const std::string &pass);

  /// Write the entire Storage object (right now just the Auth table) to the
  /// file specified by this.filename.  To ensure durability, Storage must be
  /// persisted in two steps.  First, it must be written to a temporary file
  /// (this.filename.tmp).  Then the temporary file can be renamed to replace
  /// the older version of the Storage object.
  void persist();

  /// Shut down the storage when the server stops.
  ///
  /// NB: this is only called when all threads have stopped accessing the
  ///     Storage object.  As a result, there's nothing left to do, so it's a
  ///     no-op.
  void shutdown();
};
