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
  public:

  struct bucket {
    std::vector<std::pair<K, V>> content;
    std::mutex mtx;
  };

  // daata can be vec of structs
  size_t capacity;
  std::vector<bucket*> buckets;


  /// Construct a concurrent hash table by specifying the number of buckets it
  /// should have
  ///
  /// @param _buckets The number of buckets in the concurrent hash table
  ConcurrentHashTable(size_t _buckets) {
    capacity = _buckets;
    for(size_t i = 0; i < capacity; i++){
      buckets.push_back(new bucket());
    }
  }

  ~ConcurrentHashTable() 
  { 
    for (size_t i = 0; i < capacity; ++i)
    {
      delete buckets[i];
    }
  }  

  /// Clear the Concurrent Hash Table.  This operation needs to use 2pl
  void clear() {
    for (size_t i = 0; i < capacity; ++i){
      //lock
      buckets[i]->mtx.lock();
    }
    for (size_t i = 0; i < capacity; ++i){
      //clear
      buckets[i]->content.clear();
    }
    for (size_t i = 0; i < capacity; ++i){
      //unlock
      buckets[i]->mtx.unlock();
    }
    
  }

  /// Insert the provided key/value pair only if there is no mapping for the key
  /// yet.
  ///
  /// @param key The key to insert
  /// @param val The value to insert
  ///
  /// @returns true if the key/value was inserted, false if the key already
  /// existed in the table
  bool insert(K key, V val) { 
    size_t idx = std::hash<K>()(key) % capacity;
    std::lock_guard<std::mutex> lock(buckets[idx]->mtx);
    for(size_t j = 0; j < buckets[idx]->content.size(); j++){
      if(buckets.at(idx)->content[j].first == key){
        return false;
      }
    }
    buckets[idx]->content.push_back({key, val});
    return true; 
  }

  /// Insert the provided key/value pair if there is no mapping for the key yet.
  /// If there is a key, then update the mapping by replacing the old value with
  /// the provided value
  ///
  /// @param key The key to upsert
  /// @param val The value to upsert
  ///
  /// @returns true if the key/value was inserted, false if the key already
  ///          existed in the table and was thus updated instead
  bool upsert(K key, V val) { 
    size_t idx = std::hash<K>()(key) % capacity;
    std::lock_guard<std::mutex> lock(buckets.at(idx)->mtx);
    for(size_t j = 0; j < buckets[idx]->content.size(); j++){
      if(buckets[idx]->content[j].first == key){
        buckets[idx]->content[j].second = val;
        return false;
      }
    }
    buckets[idx]->content.push_back({key, val});
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
    size_t idx = std::hash<K>()(key) % capacity;
    std::lock_guard<std::mutex> lock(buckets.at(idx)->mtx);
    for(size_t j = 0; j < buckets[idx]->content.size(); j++){
      if(buckets[idx]->content[j].first == key){
        buckets[idx]->content[j].second = f(buckets[idx]->content[j].second);
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
    size_t idx = std::hash<K>()(key) % capacity;
    std::lock_guard<std::mutex> lock(buckets.at(idx)->mtx);
    for(size_t j = 0; j < buckets[idx]->content.size(); j++){
      if(buckets[idx]->content[j].first == key){
        f(buckets[idx]->content[j].second);
        return true;
      }
    }
    return false; 
  }

  /// Remove the mapping from a key to its value
  ///
  /// @param key The key whose mapping should be removed
  ///
  /// @returns true if the key was found and the value unmapped, false otherwise
  bool remove(K key) { 
    size_t idx = std::hash<K>()(key) % capacity;
    std::lock_guard<std::mutex> lock(buckets.at(idx)->mtx);
      for(size_t j = 0; j < buckets[idx]->content.size(); j++){
        if(buckets[idx]->content[j].first == key){
          buckets[idx]->content.erase(buckets[idx]->content.begin() + j);
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
    //lock
    for(size_t i = 0; i < capacity; i++){
      buckets[i]->mtx.lock();                     
    }
    for(size_t i = 0; i < capacity; i++){
      for(size_t j = 0; j < buckets[i]->content.size(); j++){
        f(buckets[i]->content[j].first, buckets[i]->content[j].second);
      }
    }
    then();
    for(size_t i = 0; i < capacity; i++){
      buckets[i]->mtx.unlock();                     
    }
  }
};
