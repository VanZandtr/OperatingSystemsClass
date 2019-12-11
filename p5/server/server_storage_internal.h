#pragma once

#include "../common/func_table.h"
#include "../common/functypes.h"
#include "../common/hashtable.h"
#include "../common/mru.h"
#include "../common/quota_tracker.h"

#include "server_storage.h"

/// Storage::Internal is the private struct that holds all of the fields of
/// the Storage object.  Organizing the fields as an Internal is part of the
/// PIMPL pattern.
struct Storage::Internal {
  /// AuthTableEntry represents one user stored in the authentication table
  struct AuthTableEntry {
    /// The name of the user; max 64 characters
    std::string username;

    /// The hashed password.  Note that the password is a max of 128 chars
    std::string pass_hash;

    /// The user's content
    vec content;

    /// The user's upload quota
    quota_tracker uploads;

    /// The user's download quota
    quota_tracker downloads;

    /// The user's requests quota
    quota_tracker requests;
  };

  /// A unique 8-byte code to use as a prefix each time an AuthTable Entry is
  /// written to disk.
  inline static const std::string AUTHENTRY = "AUTHAUTH";

  /// A unique 8-byte code to use as a prefix each time a KV pair is written to
  /// disk.
  inline static const std::string KVENTRY = "KVKVKVKV";

  /// A unique 8-byte code for incremental persistence of changes to the auth
  /// table
  inline static const std::string AUTHDIFF = "AUTHDIFF";

  /// A unique 8-byte code for incremental persistence of updates to the kv
  /// store
  inline static const std::string KVUPDATE = "KVUPDATE";

  /// A unique 8-byte code for incremental persistence of deletes to the kv
  /// store
  inline static const std::string KVDELETE = "KVDELETE";

  /// The map of authentication information, indexed by username
  ConcurrentHashTable<std::string, AuthTableEntry> auth_table;

  /// The map of key/value pairs
  ConcurrentHashTable<std::string, vec> kv_store;

  /// filename is the name of the file from which the Storage object was loaded,
  /// and to which we persist the Storage object every time it changes
  std::string filename = "";

  /// The open file
  FILE *storage_file = nullptr;

  /// The upload quota
  const size_t up_quota;

  /// The download quota
  const size_t down_quota;

  /// The requests quota
  const size_t req_quota;

  /// The number of seconds over which quotas are enforced
  const double quota_dur;

  /// The MRU table for tracking the most recently used keys
  mru_manager mru;

  /// The name of the admin user
  std::string admin_name;

  /// The function table, to support executing map/reduce on the kv_store
  func_table funcs;

  /// Construct the Storage::Internal object by setting the filename and bucket
  /// count
  ///
  /// @param fname       The name of the file that should be used to load/store
  ///                    the data
  /// @param num_buckets The number of buckets for the hash
  Internal(const std::string &fname, size_t num_buckets, size_t upq, size_t dnq,
           size_t rqq, double qd, size_t top, const std::string &name)
      : auth_table(num_buckets), kv_store(num_buckets), filename(fname),
        up_quota(upq), down_quota(dnq), req_quota(rqq), quota_dur(qd), mru(top),
        admin_name(name) {}
};