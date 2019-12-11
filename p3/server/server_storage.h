#pragma once

#include <memory>
#include <string>
#include <utility>

#include "../common/vec.h"

/// Storage is the main data type managed by the server.  It currently provides
/// access to two concurrent maps.  The first is an authentication table.  The
/// authentication table holds user names and hashed passwords, as well as a
/// single content object per user.  The second is a key/value store that can be
/// accessed by all threads.
///
/// The public interface of Storage provides functions that correspond 1:1 with
/// the data requests that a client can make.  In that manner, the server
/// command handlers need only parse a request, send its parts to the Storage
/// object, and then format and return the result.
///
/// Storage is a persistent object.  Persistence can be achieved by writing the
/// entire object to disk in response to SAV messages.  In addition, any
/// successful server_cmd_reg, server_cmd_set, server_cmd_kvi, server_cmd_kvu,
/// or server_cmd_kvd operation will write a "DIFF" entry to the file.  Note
/// that the file will be open at all times, so that these operations can
/// perform an fwrite followed by an fflush.  The file should only open and
/// close in response to load() and persist() calls.
///
/// We use a relatively simple binary wire format to write every Auth table
/// entry and every K/V pair to disk:
///
///  - Authentication entry format:
///    - Magic 8-byte constant AUTHAUTH
///    - 4-byte binary write of the length of the username
///    - Binary write of the bytes of the username
///    - Binary write of the length of pass_hash
///    - Binary write of the bytes of pass_hash
///    - Binary write of num_bytes
///    - If num_bytes > 0, a binary write of the bytes field
///  - K/V entry format:
///    - Magic 8-byte constant KVKVKVKV
///    - 4-byte binary write of the length of the key
///    - Binary write of the bytes of the key
///    - Binary write of the length of value
///    - Binary write of the bytes of value
///
/// We also have the following DIFF entries in the file:
///
/// - AUTHDIFF: when a user's content changes in the Auth table
///   - Magic 8-byte constant AUTHDIFF
///   - 4-byte binary write of the length of the username
///   - Binary write of the bytes of the username
///   - Binary write of num_bytes of the content
///   - If num_bytes > 0, a binary write of the bytes field
/// - KVUPDATE: when a key's value is changed via upsert
///   - Magic 8-byte constant KVUPDATE
///    - 4-byte binary write of the length of the key
///    - Binary write of the bytes of the key
///    - Binary write of the length of value
///    - Binary write of the bytes of value
/// - KVDELETE: when a key is removed from the key/value store
///   - Magic 8-byte constant KVDELETE
///    - 4-byte binary write of the length of the key
///    - Binary write of the bytes of the key
///
/// Note that there are other operations that need to incrementally persist
/// by adding to the file, but they do not need DIFF messages... they can use
/// AUTHAUTH and KVKVKVKV.
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
  Storage(const std::string &fname, size_t num_buckets);

  /// Destructor for the storage object.
  ~Storage();

  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
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

  /// Write the entire Storage object to the file specified by this.filename.
  /// To ensure durability, Storage must be persisted in two steps.  First, it
  /// must be written to a temporary file (this.filename.tmp).  Then the
  /// temporary file can be renamed to replace the older version of the Storage
  /// object.
  void persist();

  /// Create a new key/value mapping in the table
  ///
  /// @param user_name The name of the user who made the request
  /// @param pass      The password for the user, used to authenticate
  /// @param key       The key whose mapping is being created
  /// @param val       The value to copy into the map
  ///
  /// @returns A vec with the result message
  vec kv_insert(const std::string &user_name, const std::string &pass,
                const std::string &key, const vec &val);

  /// Get a copy of the value to which a key is mapped
  ///
  /// @param user_name The name of the user who made the request
  /// @param pass      The password for the user, used to authenticate
  /// @param key       The key whose value is being fetched
  ///
  /// @returns A pair with a bool to indicate error, and a vector indicating the
  ///          data (possibly an error message) that is the result of the
  ///          attempt.
  std::pair<bool, vec> kv_get(const std::string &user_name,
                              const std::string &pass, const std::string &key);

  /// Delete a key/value mapping
  ///
  /// @param user_name The name of the user who made the request
  /// @param pass      The password for the user, used to authenticate
  /// @param key       The key whose value is being deleted
  ///
  /// @returns A vec with the result message
  vec kv_delete(const std::string &user_name, const std::string &pass,
                const std::string &key);

  /// Insert or update, so that the given key is mapped to the give value
  ///
  /// @param user_name The name of the user who made the request
  /// @param pass      The password for the user, used to authenticate
  /// @param key       The key whose mapping is being upserted
  /// @param val       The value to copy into the map
  ///
  /// @returns A vec with the result message.  Note that there are two "OK"
  ///          messages, depending on whether we get an insert or an update.
  vec kv_upsert(const std::string &user_name, const std::string &pass,
                const std::string &key, const vec &val);

  /// Return all of the keys in the kv_store, as a "\n"-delimited string
  ///
  /// @param user_name The name of the user who made the request
  /// @param pass      The password for the user, used to authenticate
  ///
  /// @returns A pair with a bool to indicate errors, and a vec with the result
  ///          (possibly an error message).
  std::pair<bool, vec> kv_all(const std::string &user_name,
                              const std::string &pass);

  /// Close any open files related to incremental persistence
  ///
  /// NB: this cannot be called until all threads have stopped accessing the
  ///     Storage object
  void shutdown();
};