#include <deque>
#include <mutex>
#include <iostream>

#include "mru.h"

using namespace std;

/// mru_manager::Internal is the class that stores all the members of a
/// mru_manager object. To avoid pulling too much into the .h file, we are using
/// the PIMPL pattern
/// (https://www.geeksforgeeks.org/pimpl-idiom-in-c-with-examples/)
struct mru_manager::Internal {

  size_t elements;
  deque<std::string> queue;

  /// Construct the Internal object by setting the fields that are
  /// user-specified
  ///
  /// @param elements The number of elements that can be tracked
  Internal(size_t elements) {
    this->elements = elements;
  }
};

/// Construct the mru_manager by specifying how many things it should track
mru_manager::mru_manager(size_t elements) : fields(new Internal(elements)) {}

/// Destruct an mru_manager
mru_manager::~mru_manager() = default;

/// Insert an element into the mru_manager, making sure that (a) there are no
/// duplicates, and (b) the manager holds no more than /max_size/ elements.
///
/// @param elt The element to insert
void mru_manager::insert(const string &elt) {
  //check for duplicates
  bool duplicate_found = 0;
  for(size_t i = 0; i < fields->queue.size(); i++){
    if(fields->queue[i].compare(elt) == 0){
      duplicate_found = 1;

      //push that value to the front
      string temp = fields->queue.at(i);
      fields->queue.erase(fields->queue.begin() + i);
      fields->queue.push_front(temp);
      break;
    }
  }

  if(duplicate_found == 1){
    //cout << "FOUND DUPLICATE: "<< elt <<endl;
    //do nothing
  }
  
  else if (fields->queue.size() == fields->elements){
    //cout << "REMOVING LAST ELEMENT: "<< fields->queue[fields->elements-1] << endl;
    //remove last ele
    fields->queue.pop_back();    
    //cout << "PUSHING ELEMENT: "<< elt << endl;
    //insert
    fields->queue.push_front(elt);
  }

  else{
    //cout << "Inserting: "<< elt <<endl;
    //insert
    fields->queue.push_front(elt);
  }

  //checking contents
  for(size_t i = 0; i < fields->queue.size(); i++){
    //cout << "MRU LOOP [" << i << "]: "<< fields->queue[i] << endl;
  }
  
}

/// Remove an instance of an element from the mru_manager.  This can leave the
/// manager in a state where it has fewer than max_size elements in it.
///
/// @param elt The element to remove
void mru_manager::remove(const string &elt) {
  cout << "REMOVING: "<< elt << endl;
  for(size_t i = 0; i < fields->queue.size(); i++){
    cout << "MRU LOOP [" << i << "]: "<< fields->queue[i] << endl;
  }
  for(size_t i =0; i < fields->queue.size(); i++){
    if(fields->queue[i].compare(elt) == 0){
      fields->queue.erase(fields->queue.begin() + i);
    }
  }
  for(size_t i = 0; i < fields->queue.size(); i++){
    cout << "MRU LOOP [" << i << "]: "<< fields->queue[i] << endl;
  }
}

/// Clear the mru_manager
void mru_manager::clear() {
  fields->queue.clear();
}

/// Produce a concatenation of the top entries, in order of popularit
///
/// @returns A newline-separated list of values
string mru_manager::get() { 
  if(fields->queue.size() == 0){
    return ""; 
  }

  string ret = "";
  for(size_t i =0; i < fields->queue.size(); i++){
    ret += fields->queue[i];
    ret += '\n';
  }
  return ret;
};