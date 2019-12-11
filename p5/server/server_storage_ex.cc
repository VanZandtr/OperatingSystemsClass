#include <sys/wait.h>
#include <unistd.h>
#include <iostream>
#include <algorithm>
#include <fcntl.h>
#include <cerrno>
#include <string.h>
#include <stdio.h>


#include "../common/contextmanager.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "server_storage.h"
#include "server_storage_internal.h"

using namespace std;

/// Perform the child half of a map/reduce communication
///
/// @param in_fd   The fd from which to read data from the parent
/// @param out_fd  The fd on which to write data to the parent
/// @param mapper  The map function to run on each pair received from the
///                parent
/// @param reducer The reduce function to run on the results of mapper
///
/// @returns false if any error occurred, true otherwise
bool child_mr(int in_fd, int out_fd, map_func mapper, reduce_func reducer)
{
  cerr << "In child process" << endl;

  //vector to hold all mapper returns
  std::vector<vec> map_vec;

  if(fcntl(in_fd, F_GETFD) != 0){
    cerr << "in_fd is not open/valid" << endl;
  }
  if(fcntl(out_fd, F_GETFD) != 0){
    cerr << "out_fd is not open/valid" << endl;
  }
  

  while (true)
  {
    //key length
    char key_len_char[4];
    int read_check = read(in_fd, &key_len_char, 4);
    cerr << "key_len_char: " << key_len_char << endl;
    if (read_check == 0)
    {
      //got EOF
      cerr << "EOF" << endl;
      break;
    }
    else if (read_check == -1)
    {
      //read error
      cerr << "read check == -1" << endl;
      return false;
    }
    int key_len = atoi(key_len_char);
    cerr << "key_len: " << key_len << endl;

    //key
    char key_char[key_len];
    if (read(in_fd, key_char, key_len) < 1)
    {
      cerr << "child read error1" << endl;
      cerr << errno << endl;
      cerr << strerror(errno) << endl;
      return false;
    }
    string key(key_char);
    cerr << "key: ";
    cerr << key << endl;

    //val length
    char val_len_char[4];
    if (read(in_fd, val_len_char, 4) < 1)
    {
      //read error
      cerr << "child read error2" << endl;
      return false;
    }
    int val_len = atoi(val_len_char);
    cerr << "val len: ";
    cerr << val_len << endl;

    //val
    // make a vec like this:
    vec val(val_len);

    // then read into val.data()
    if (read(in_fd, val.data(), val_len) < 1)
    {
      //read error
      cerr << "child read error3" << endl;
      return false;
    }
  
    //run mapper
    vec map_ret = mapper(key, val);
    cerr << "mapper succeeded "<< endl;

    //add to map_vec
    map_vec.push_back(map_ret);
  }

  cerr << "going to reducer "<< endl;

  //run reduce
  vec reduce_vec = reducer(map_vec);

  cerr << "reducer succeeded "<< endl;

  // write twice: the size, then the data
  int rvs = reduce_vec.size();
  if (write(out_fd, &rvs, 4) == -1)
  {
    //child write error
    cerr << "child write error"<< endl;
    return false;
  }

  if (write(out_fd, reduce_vec.data(), reduce_vec.size()) == -1)
  {
    //child write error
    cerr << "child write error"<< endl;
    return false;
  }

  cerr << "child done"<< endl;

  return true;
}

/// Register a .so with the function table
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param mrname    The name to use for the registration
/// @param so        The .so file contents to register
///
/// @returns A vec with the result message
vec Storage::register_mr(const string &user_name, const string &pass,
                         const string &mrname, const vec &so)
{
  if (user_name != fields->admin_name)
  {
    return vec_from_string(RES_ERR_LOGIN);
  }

  //auth user
  if (auth(user_name, pass) == false)
  {
    return vec_from_string(RES_ERR_LOGIN);
  }
  
  vec ret = fields->funcs.register_mr(mrname, so);
  return ret;
};

/// Run a map/reduce on all the key/value pairs of the kv_store
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, to authenticate
/// @param mrname    The name of the map/reduce functions to use
///
/// @returns A pair with a bool to indicate error, and a vector indicating the
///          message (possibly an error message) that is the result of the
///          attempt
pair<bool, vec> Storage::invoke_mr(const string &user_name, const string &pass, const string &mrname)
{
  ///
  //do without fork to test func_table
  
/*
  std::vector<vec> map_vec;
  
  //get functions
  pair<map_func, reduce_func> func_pair = fields->funcs.get_mr(mrname);
  
  //check if nullptr
  if (func_pair.first == nullptr)
  {
    //cerr << "func_pair is nullptr" << endl;
    return {true, vec_from_string(RES_ERR_FUNC)};
  }
  
  //get all pairs -> pass to mapper

  auto lmbd = [&](string k, vec v) {
    //run mapper
    vec map_ret = func_pair.first(k, v);
    
    //add to map_vec
    map_vec.push_back(map_ret);
  };
  fields->kv_store.do_all_readonly(lmbd, []() {});
  
  //run reduce
  vec reduce_vec = func_pair.second(map_vec);

  return {false, reduce_vec};
  
  ///
*/
  ///WITH FORKING!
  
  
  cerr << "username: " << user_name << endl;
  cerr << "pass: " << pass << endl;
  cerr << "mrname: " << mrname << endl;

  //DOESNT NEED TO BE ADMIN
  if (auth(user_name, pass) == false)
  {
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }

  cerr << "User authed" << endl;

  //get functions
  pair<map_func, reduce_func> func_pair = fields->funcs.get_mr(mrname);

  //check if nullptr
  if (func_pair.first == nullptr)
  {
    cerr << "func_pair is nullptr" << endl;
    return {true, vec_from_string(RES_ERR_FUNC)};
  }

  int fd1[2]; // Used to store two ends of first pipe
  int fd2[2]; // Used to store two ends of second pipe

  if (pipe(fd1) == -1)
  {
    cerr << "Pipe1 failed" << endl;
    return {true, vec_from_string(RES_ERR_SO)};
  }

  if (pipe(fd2) == -1)
  {
    cerr << "Pipe2 failed" << endl;
    return {true, vec_from_string(RES_ERR_SO)};
  }

  pid_t p = fork();

  if (p < 0)
  {
    cerr << "Fork failed" << endl;
    return {true, vec_from_string(RES_ERR_SO)};
  }

  // Parent process
  if (p > 0)
  {
    cerr << "In parent process" << endl;


    bool lmbd_err = false;

    //vec to_send;
    auto lmbd = [&](string k, vec v) {
      
      //sizeof(key).key.sizeof(value).value
      int kl = k.length();
      if (write(fd1[1], &kl, sizeof(kl)) == -1)
      {
        cerr << "lambda write error1" << endl;
        lmbd_err = true;
        return; // x3
      }

      if (write(fd1[1], k.c_str(), kl) == -1)
      {
        cerr << "lambda write error2" << endl;
        lmbd_err = true;
        return;
      }

      int vs = v.size();
      if (write(fd1[1], &vs, 4) == -1)
      {
        cerr << "lambda write error3" << endl;
        lmbd_err = true;
        return;
      }

      if (write(fd1[1], v.data(), v.size()) == -1)
      {
        cerr << "lambda write error4" << endl;
        lmbd_err = true; 
        return;
      }
      
      //cerr << "kl: " << kl << endl;
      //cerr << "k: " << k << endl;
      //cerr << "vs: " << vs << endl;
      //cerr << "v: " << v.data() << endl;
    };

    //do_all_readonly func - do I do this on kv_store or the functions?
    fields->kv_store.do_all_readonly(lmbd, [](){});

    cerr << "after do all readonly" << endl;
      
    if(lmbd_err == true){
      cerr << "lambda error" << endl;
      return {true, vec_from_string(RES_ERR_SERVER)};
    }

    //close writing end to let child know when to EOF
    close(fd1[1]);


    //read from child the size of incoming vec
    int incoming_size;
    if (read(fd2[0], &incoming_size, 4) <= 0)
    {
      cerr << "error reading from child" << endl;
      return {true, vec_from_string(RES_ERR_FUNC)};
    }

    cerr << "read incoming_size" << endl;
    
    //Read string from child
    vec child_ret(incoming_size);
    if (read(fd2[0], child_ret.data(), incoming_size) <= 0)
    {
      cerr << "error reading from child" << endl;
      return {true, vec_from_string(RES_ERR_FUNC)};
    }

    cerr << "read child's return" << endl;

    // Wait for child to send a string
    int status;
    waitpid(p, &status, 0);
    cerr << status << endl;

    cerr << "parent done" << endl;
    //close everything
    close(fd1[0]);
    close(fd2[1]);
    close(fd2[0]);
    return {false, child_ret};
  }

  // child process
  else
  {
    
    //what mapper and reducer to pass?
    bool child_ret = child_mr(fd1[0], fd2[1], func_pair.first, func_pair.second);
    if (child_ret == false)
    {
      cerr << "error so of child_mr" << endl;
      exit(0);
      return {true, vec_from_string(RES_ERR_SO)};
    }
    exit(0);
  }

  return {true, vec_from_string(RES_ERR_SO)};
  
}
