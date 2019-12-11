#include <atomic>
#include <dlfcn.h>
#include <iostream>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>
#include <fstream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "../common/contextmanager.h"
#include "../common/file.h"
#include "../common/functypes.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "func_table.h"

using namespace std;

/// func_table::Internal is the private struct that holds all of the fields of
/// the func_table object.  Organizing the fields as an Internal is part of the
/// PIMPL pattern.
///
/// Among other things, this struct will probably need to have a map of loaded
/// functions and a shared_mutex.  The map will probably need to hold some kind
/// of struct that is able to support graceful shutdown, as well as the
/// association of names to map/reduce functions
struct func_table::Internal
{
  //variables
  std::map<string, pair<map_func, reduce_func>> functions;
  std::vector<void *> handles;
  std::shared_mutex mtx;
};

/// Construct a function table for storing registered functions
func_table::func_table() : fields(new Internal()) {}

/// Destruct a function table
func_table::~func_table() = default;

/// Register the map() and reduce() functions from the provided .so, and
/// associate them with the provided name.
///
/// @param mrname The name to associate with the functions
/// @param so     The so contents from which to find the functions
///
/// @returns a vec with a status message
vec func_table::register_mr(const string &mrname, const vec &so)
{
  fields->mtx.lock();

  cerr << "mrname: " << mrname << " so: " << so.size() << endl;
  //check length
  if (mrname.length() > LEN_FNAME)
  {
    fields->mtx.unlock();
    cerr << "mrname too long" << endl;
    return vec_from_string(RES_ERR_FUNC);
  }

  //check if already exists
  /*for (auto it = fields->functions.begin(); it != fields->functions.end(); ++it)
  {
    if (mrname.compare(it->first) == 0)
    {
      fields->mtx.unlock();
      cerr << "it->first";
      cerr << it->first << endl;
      cerr << "mrname";
      cerr << mrname << endl;
      
      return vec_from_string(RES_ERR_FUNC);
    }
  }*/

  //get a unique file name
  string filename;
  void *mf;
  void *rf;

  filename = "./" + mrname+ ".so";
  cerr << "filename is: " << filename << endl;
  //make the file and read so into it
  fstream file;
  file.open(filename, ios::out);
  for (const auto &i : so)
    file << i;

  file.close();

  //open made file with dlopen
  void *handle = dlopen((const char *)filename.c_str(), RTLD_NOW | RTLD_LAZY);
  cerr << "handle: " << handle << endl;
  cerr << "name: " << filename.c_str() << endl;
  if (!handle)
  {
    cerr << "dlopen error is: " << dlerror() << endl;
    fields->mtx.unlock();
    return vec_from_string(RES_ERR_SO);
  }
  else
  {
    cerr << "DLOpen successful!\n";
  }

  //use dlsym to get mapper and reducer --> set to mf and rf above
  mf = dlsym(handle, "map");
  rf = dlsym(handle, "reduce");

  //push handle to vec
  fields->handles.push_back(handle);

  //we can delete and have the so open as well
  if (remove((const char *)filename.c_str()) != 0)
  {
    fields->mtx.unlock();
    cerr << "error deleting file" << endl;
    return vec_from_string(RES_ERR_FUNC);
  }

  //add to map
  auto ptr = fields->functions.insert({mrname, {(map_func)mf, (reduce_func)rf}});
  cerr << "functions size line 133: " << fields->functions.size() << endl;
  if (!ptr.second)
  {
    //was not inserted
    fields->mtx.unlock();
    cerr << "not inserted" << endl;
    return vec_from_string(RES_ERR_FUNC);
  }

  fields->mtx.unlock();

  //returns OK instead of server terminated?
  return vec_from_string(RES_OK);
}

/// Get the (already-registered) map() and reduce() functions asssociated with
/// a name.
///
/// @param name The name with which the functions were mapped
///
/// @returns A pair of function pointers, or {nullptr, nullptr} on error
pair<map_func, reduce_func> func_table::get_mr(const string &mrname)
{
  cerr << "get_mr" << endl;
  if(!fields->mtx.try_lock_shared()){
    cerr << "in if statment" << endl;
    fields->mtx.unlock_shared();
    fields->mtx.lock_shared();
  }
  else{
    cerr << "we good" << endl;
  }
  
  //loop through map
  int i = 0;
  cerr << "functions.size(): " << fields->functions.size() << endl;
  for (auto it = fields->functions.begin(); it != fields->functions.end(); ++it)
  {
    if ((it->first).compare(mrname) == 0)
    {
      //copy
      pair <map_func, reduce_func> copy_pair;
      copy_pair = it->second;

      //unlock
      fields->mtx.unlock_shared();

      //return copy
      return copy_pair;
    }
    i++;
  }
  fields->mtx.unlock_shared();
  return {nullptr, nullptr};
}

/// When the function table shuts down, we need to de-register all the .so
/// files that were loaded.
void func_table::shutdown()
{
  cerr << "in shutdown" << endl;
  for (size_t i = 0; i < fields->handles.size(); i++)
  {
    dlclose(fields->handles[i]);
  }
}