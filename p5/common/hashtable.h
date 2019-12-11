#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>

/// ConcurrentHashTable is a concurrent hash table (a Key/Value store).  It is
/// not resizable, which means that the O(1) guarantees of a hash table are lost
/// if the number of elements in the table gets too big.
///
/// The ConcurrentHashTable is templated on the Key and Value types
///
/// The general structure of the ConcurrentHashTable is that we have an array of
/// buckets.  Each bucket has a mutex and a vector of entries.  Each entry is a
/// pair, consisting of a key and a value.  We can use std::hash() to choose a
/// bucket from a key.
template <typename K, typename V> class ConcurrentHashTable {
  /// A bucket_t is a lockable vector of key/value pairs
  struct bucket_t {
    /// A lock, for protecting this bucket
    std::mutex lock;

    /// The vector of key/value pairs in this bucket
    std::vector<std::pair<K, V>> pairs;
  };

  /// The number of buckets in our non-resizable concurrent HashTable
  const size_t num_buckets;

  /// The table of buckets.  Note that we store pointers to bucket_t, not
  /// bucket_t's themselves, so that locks are less likely to be on the same
  /// cache line.
  std::vector<bucket_t *> buckets;

public:
  /// Construct a concurrent hash table by specifying the number of buckets it
  /// should have
  ///
  /// @param _buckets The number of buckets in the concurrent hash table
  ConcurrentHashTable(size_t _buckets) : num_buckets(_buckets) {
    for (size_t i = 0; i < num_buckets; ++i) {
      buckets.emplace_back(new bucket_t());
    }
  }

  /// Clear the Concurrent Hash Table.  This operation needs to use 2pl
  void clear() {
    /// We'll use "strict" 2pl... first we acquire all locks, then we do all
    /// operations, then we release all locks.
    for (auto b : buckets)
      b->lock.lock();
    for (auto b : buckets)
      b->pairs.clear();
    for (auto b : buckets)
      b->lock.unlock();
  }

  /// Insert the provided key/value pair only if there is no mapping for the key
  /// yet.
  ///
  /// @param key        The key to insert
  /// @param val        The value to insert
  /// @param on_success Code to run if the insertion succeeds
  ///
  /// @returns true if the key/value was inserted, false if the key already
  ///          existed in the table
  bool insert(K key, V val, std::function<void()> on_success) {
    using namespace std;
    size_t b = hash<K>{}(key) % num_buckets;
    lock_guard<mutex> g(buckets[b]->lock);
    for (const auto &e : buckets[b]->pairs) {
      if (e.first == key)
        return false;
    }
    buckets[b]->pairs.push_back({key, val});
    on_success();
    return true;
  }

  /// Insert the provided key/value pair if there is no mapping for the key yet.
  /// If there is a key, then update the mapping by replacing the old value with
  /// the provided value
  ///
  /// @param key    The key to upsert
  /// @param val    The value to upsert
  /// @param on_ins Code to run if the upsert succeeds as an insert
  /// @param on_upd Code to run if the upsert succeeds as an update
  ///
  /// @returns true if the key/value was inserted, false if the key already
  ///          existed in the table and was thus updated instead
  bool upsert(K key, V val, std::function<void()> on_ins,
              std::function<void()> on_upd) {
    using namespace std;
    auto b = hash<K>{}(key) % num_buckets;
    lock_guard<mutex> g(buckets[b]->lock);
    for (auto &e : buckets[b]->pairs) {
      if (e.first == key) {
        e.second = val;
        on_upd();
        return false;
      }
    }
    buckets[b]->pairs.push_back({key, val});
    on_ins();
    return true;
  }

  /// Apply a function to the value associated with a given key.  The function
  /// is allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @returns true if the key existed and the function was applied, false
  ///          otherwise
  bool do_with(K key, std::function<void(V &)> f) {
    using namespace std;
    size_t b = hash<K>{}(key) % num_buckets;
    lock_guard<mutex> g(buckets[b]->lock);
    for (auto &e : buckets[b]->pairs) {
      if (e.first == key) {
        f(e.second);
        return true;
      }
    }
    return false;
  }

  /// Apply a function to the value associated with a given key.  The function
  /// is not allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @returns true if the key existed and the function was applied, false
  ///          otherwise
  bool do_with_readonly(K key, std::function<void(const V &)> f) {
    using namespace std;
    auto b = hash<K>{}(key) % num_buckets;
    lock_guard<mutex> g(buckets[b]->lock);
    for (const auto &e : buckets[b]->pairs) {
      if (e.first == key) {
        f(e.second);
        return true;
      }
    }
    return false;
  }

  /// Remove the mapping from a key to its value
  ///
  /// @param key        The key whose mapping should be removed
  /// @param on_success Code to run if the remove succeeds
  ///
  /// @returns true if the key was found and the value unmapped, false otherwise
  bool remove(K key, std::function<void()> on_success) {
    using namespace std;
    size_t b = hash<K>{}(key) % num_buckets;
    lock_guard<mutex> g(buckets[b]->lock);
    for (auto i = buckets[b]->pairs.begin(), e = buckets[b]->pairs.end();
         i != e; ++i) {
      if (i->first == key) {
        buckets[b]->pairs.erase(i);
        on_success();
        return true;
      }
    }
    return false;
  }

  /// Apply a function to every key/value pair in the ConcurrentHashTable.  Note
  /// that the function is not allowed to modify keys or values.
  ///
  /// @param f    The function to apply to each key/value pair
  /// @param then A function to run when this is done, but before unlocking...
  ///             useful for 2pl
  void do_all_readonly(std::function<void(const K, const V &)> f,
                       std::function<void()> then) {
    /// We'll use "strict" 2pl... first we acquire all locks, then we do all
    /// operations, then we release all locks.
    for (auto b : buckets)
      b->lock.lock();
    for (auto b : buckets) {
      for (const auto &e : b->pairs) {
        f(e.first, e.second);
      }
    }
    // Before releasing locks, run the 'then'
    then();
    for (auto b : buckets)
      b->lock.unlock();
  }
};
