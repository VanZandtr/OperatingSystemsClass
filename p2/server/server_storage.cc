#include <iostream>
#include <fstream>
#include <openssl/md5.h>
#include <unordered_map>
#include <utility>
#include <string.h>
#include <stdio.h>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/hashtable.h"
#include "../common/protocol.h"
#include "../common/vec.h"
#include "../common/file.h"
#include "server_storage.h"

using namespace std;

/// Storage::Internal is the private struct that holds all of the fields of the
/// Storage object.  Organizing the fields as an Internal is part of the PIMPL
/// pattern.
struct Storage::Internal
{
  /// AuthTableEntry represents one user stored in the authentication table
  struct AuthTableEntry
  {
    /// The name of the user; max 64 characters
    string username;

    /// The hashed password.  Note that the password is a max of 128 chars
    string pass_hash;

    /// The user's content
    vec content;
  };

  /// A unique 8-byte code to use as a prefix each time an AuthTable Entry is
  /// written to disk.
  inline static const string AUTHENTRY = "AUTHAUTH";

  /// A unique 8-byte code to use as a prefix each time a KV pair is written to
  /// disk.
  inline static const string KVENTRY = "KVKVKVKV";

  /// The map of authentication information, indexed by username
  ConcurrentHashTable<string, AuthTableEntry> auth_table;

  /// The map of key/value pairs
  ConcurrentHashTable<string, vec> kv_store;


  /// filename is the name of the file from which the Storage object was loaded,
  /// and to which we persist the Storage object every time it changes
  string filename = "";

  /// Construct the Storage::Internal object by setting the filename and bucket
  /// count
  ///
  /// @param fname       The name of the file that should be used to load/store
  ///                    the data
  /// @param num_buckets The number of buckets for the hash
  Internal(string fname, size_t num_buckets)
      : auth_table(num_buckets), kv_store(num_buckets), filename(fname) {}
};

/// Construct an empty object and specify the file from which it should be
/// loaded.  To avoid exceptions and errors in the constructor, the act of
/// loading data is separate from construction.
///
/// @param fname       The name of the file that should be used to load/store
///                    the data
/// @param num_buckets The number of buckets for the hash
Storage::Storage(const string &fname, size_t num_buckets)
    : fields(new Internal(fname, num_buckets)) {}

/// Destructor for the storage object.
///
/// NB: The compiler doesn't know that it can create the default destructor in
///     the .h file, because PIMPL prevents it from knowing the size of
///     Storage::Internal.  Now that we have reified Storage::Internal, the
///     compiler can make a destructor for us.
Storage::~Storage() = default;

/// Populate the Storage object by loading this.filename.  Note that load()
/// begins by clearing the maps, so that when the call is complete,
/// exactly and only the contents of the file are in the Storage object.
///
/// @returns false if any error is encountered in the file, and true
///          otherwise.  Note that a non-existent file is not an error.
bool Storage::load()
{
  //check file exists
  FILE *f = fopen(fields->filename.c_str(), "r");
  if (f == nullptr) {
    cerr << "File not found: " << fields->filename << endl;
    return true;
  }
  fclose(f);

  //clear
  fields->auth_table.clear();
  fields->kv_store.clear();

  //load auth table from file
  std::ifstream myFile (fields->filename, std::ifstream::binary);
  //open the file
  if(myFile){
    while(!myFile.eof()){

      char h[9];
      myFile.read(h, 8);
      h[8] = '\0';
      string header(h);


      //cerr << "header: ";
      //cerr << header <<endl;

      //check if AUTHAUTH
      if(header.compare("AUTHAUTH") == 0){
        //read username length
        char ul[5]; 
        myFile.read(ul, 4);
        ul[4] = '\0';


        //cerr << "ul: ";
        //cerr << ul << endl;

        int username_length = atoi(ul);
        if(username_length > LEN_UNAME){
          myFile.close();
          return false;
        }

        //cerr << "u length: ";
        //cerr << username_length <<endl;


        //read username
        char u[username_length + 1];
        myFile.read(u, username_length);
        u[username_length] = '\0';
        string username(u);

        //cerr << "user: ";
        //cerr << username <<endl;


        //read pass length
        char phl[5];
        myFile.read(phl, 4);
        phl[4] = '\0';
        
        //cerr <<"phl: ";
        //cerr << phl <<endl;

        int pass_hash_length = atoi(phl);
        
        if(pass_hash_length > LEN_PASS){
          myFile.close();
          return false;
        }

        //read pass hash
        char ph[pass_hash_length + 1];        
        myFile.read(ph, pass_hash_length);
        ph[pass_hash_length] = '\0';

        //cerr << "ph: ";
        //cerr << ph << endl;

        string pass_hash(ph);

        //cerr << "passhash: ";
        //cerr << pass_hash <<endl;

        //read content size
        char cs[5];
        myFile.read(cs, 4);
        cs[4] = '\0';


        //cerr << "cs: ";
        //cerr << cs << endl;

        int content_size = atoi(cs);
        if(content_size > LEN_CONTENT){
          myFile.close();
          return false;
        }

        //cerr << "content size: ";
        //cerr << content_size <<endl;

        //set Entry data
        Internal::AuthTableEntry entry;

        if(content_size > 0){
          //read content data
          char cd[content_size + 1];
          myFile.read(cd, content_size);
          cd[content_size] = '\0';
          string content_data(cd);

          entry.username = username;
          entry.pass_hash = pass_hash;
          entry.content = vec_from_string(content_data);
          
        }
        else{
          entry.username = username;
          entry.pass_hash = pass_hash;
          entry.content = {};
          
          string u1 = entry.username;
          string p1 = entry.pass_hash;
          
          //cerr << u1 << endl;
          //cerr << p1 << endl;
          //cerr << "content size == 0 "<<endl;
        }

        fields->auth_table.insert(username, entry);
      }
      else if (header.compare("KVKVKVKV") == 0){
        char kl[5];
        myFile.read(kl, 4);
        kl[4] = '\0';

        //cerr << "kl: ";
        //cerr << kl << endl;

        int key_length = atoi(kl);
        if(key_length > LEN_KEY){
          myFile.close();
          return false;
        }

        //cerr << "keylength: ";
        //cerr << key_length << endl;

        //get the key
        char k[key_length + 1];
        myFile.read(k, key_length);
        k[key_length] = '\0';
        string key(k);

        //cerr << "key: ";
        //cerr << key << endl;

        //get val length and check
        char vl[5];
        myFile.read(vl, 4);
        vl[4] = '\0';

        int val_length = atoi(vl);
        if(val_length > LEN_VAL){
          myFile.close();
          return false;
        }

        //get val
        char v[val_length + 1];
        myFile.read(v, val_length);
        v[val_length] = '\0';
        string val(v);

        //cerr << val << endl;
        
        vec val_vec = vec_from_string(val);
        fields->kv_store.insert(key, val_vec);
      }
      else{
        //no eof and read wrong bytes
        myFile.close();
        return false;
      }
    }
    myFile.close();
  }
  cerr << "Loaded: ";
  cerr << fields->filename << endl;
  return true;
}



/// Create a new entry in the Auth table.  If the user_name already exists, we
/// should return an error.  Otherwise, hash the password, and then save an
/// entry with the username, hashed password, and a zero-byte content.
///
/// @param user_name The user name to register
/// @param pass      The password to associate with that user name
///
/// @returns False if the username already exists, true otherwise
bool Storage::add_user(const string &user_name, const string &pass)
{
  //check if username is too long
  if (user_name.length() > LEN_UNAME)
  {
    //cerr << "Username too long."<< endl;
    return false;
  }

  //check if pass_hash is too long
  if (pass.length() > LEN_PASS)
  {
    //cerr << "Password too long." << endl;
    return false;
  }

  bool b = true;
  //returns true if who doesn't exsist
  fields->auth_table.do_with_readonly(user_name, [&](const Internal::AuthTableEntry &e){ 
    //use e to set b
    if(e.username == user_name){
      // cerr << RES_ERR_USER_EXISTS << endl;
      b = false;
    }
  });
  if(b == false){
    return false;
  }

  //hash the password
  size_t pass_hash = hash<string>()(pass);
  string pass_hash_string = to_string(pass_hash);

  //set Entry data
  Internal::AuthTableEntry entry;
  entry.username = user_name;
  entry.pass_hash = pass_hash_string;
  entry.content = {};

  if(fields->auth_table.insert(user_name, entry) == false){
    b = false;
  }

  return b;
}

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
vec Storage::set_user_data(const string &user_name, const string &pass,
                           const vec &content)
{
  //auth user
  bool user_authed = auth(user_name, pass);
  if (user_authed == false)
  {
    // cerr << RES_ERR_LOGIN << endl;
    return vec_from_string(RES_ERR_LOGIN);
  }

  Internal::AuthTableEntry entry;
  entry.username = user_name; 
  entry.pass_hash = std::hash<std::string>{}(pass);
  entry.content = content;

  if(fields->auth_table.upsert(user_name, entry) == false){
    //cerr << "upsert updated key's value" << endl;
    return vec_from_string(RES_OK);
  }

  return vec_from_string(RES_OKINS);
}

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
pair<bool, vec> Storage::get_user_data(const string &user_name,
                                       const string &pass, const string &who)
{
  //auth user
  bool user_authed = auth(user_name, pass);
  if (user_authed == false)
  {
    // cerr << RES_ERR_LOGIN << endl;
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }

  pair<bool,vec> b = {};
  auto res = fields->auth_table.do_with_readonly(who, [&](const Internal::AuthTableEntry &e){ 
    //use e to set b
    if(e.username != who){
      b = {true, vec_from_string(RES_ERR_NO_USER)};
    }
    else if(e.username == who && !e.content.empty()){
      b = {false, e.content};
    }
    else{
      b = {true, vec_from_string(RES_ERR_NO_DATA)};
    }
  });

  if (res == false){
    //cerr << "error with finding key in do_with_readonly" << endl;
    b = {true, vec_from_string(RES_ERR_KEY)};
  }

  return b;
}

/// Return a newline-delimited string containing all of the usernames in the
/// auth table
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns A vector with the data, or a vector with an error message
pair<bool, vec> Storage::get_all_users(const string &user_name,
                                       const string &pass)
{
  //auth user
  bool user_authed = auth(user_name, pass);
  if (user_authed == false)
  {
    // cerr << RES_ERR_LOGIN << endl;
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }

  vec names;
  //do_all_readonly takes std::function<void(const K, const V &)> f
  auto at = [&](const string k ,const Internal::AuthTableEntry &e){
    vec_append(names, k);
    vec_append(names, "\n");
  };

  fields->auth_table.do_all_readonly(at, [](){});
  return{false, names};
}

/// Authenticate a user
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///

/// @returns True if the user and password are valid, false otherwise
bool Storage::auth(const string &user_name, const string &pass)
{
  bool b = true;
  
  size_t given_pass_hash = hash<string>()(pass);
  std::string given_pass_hash_str = to_string(given_pass_hash);
  
  auto res = fields->auth_table.do_with_readonly(user_name, [&](const Internal::AuthTableEntry &e){ 

    //use e to set b
    if(e.username != user_name){
      // cerr << RES_ERR_NO_USER << endl;
      b = false;
    }
    else if(e.pass_hash.compare(given_pass_hash_str) != 0){
      // cerr << RES_ERR_LOGIN << endl;
      b = false;
    }
  });

  if(res == false){
    //cerr << "key failure in auth for do_with_readonly" <<endl;
    b = false;
  }

  return b;
}

/// Pad a string with 0 characters to get it to size 4
void pad0_to_4(string &s){
  // check if  vec is larger than sz
  if (s.length() >= 4){
    //do nothing --- we dont need to pad
  }
  s.insert(s.begin(), 4 - s.length(), '0');
}


/// Write the entire Storage object to the file specified by this.filename.
/// To ensure durability, Storage must be persisted in two steps.  First, it
/// must be written to a temporary file (this.filename.tmp).  Then the
/// temporary file can be renamed to replace the older version of the Storage
/// object.
void Storage::persist()
{
  vec data;
  data.reserve(LEN_CONTENT);
  //do all readonly(1st data str, 2nd data str)

  auto at = [&](const string k, const Internal::AuthTableEntry &e){ 
    //save user from auth_table entry to file
    vec_append(data, "AUTHAUTH");

    string u_size = to_string(e.username.length());
    pad0_to_4(u_size);

    vec_append(data, u_size);
    vec_append(data, e.username);

    string p_size = to_string(e.pass_hash.length());
    pad0_to_4(p_size);

    vec_append(data, p_size);
    vec_append(data, e.pass_hash);

    string c_size = to_string(e.content.size());
    pad0_to_4(c_size);

    vec_append(data, c_size);
    if (e.content.size() > 0)
    {
      vec_append(data, e.content);
    }
  };

  auto kv = [&](){fields->kv_store.do_all_readonly([&](const string k, const vec &v){
    vec_append(data, "KVKVKVKV");

    string k_size = to_string(k.size());
    pad0_to_4(k_size);
    vec_append(data, k_size);
    vec_append(data, k);

    string v_size = to_string(v.size());
    pad0_to_4(v_size);
    vec_append(data, v_size);
    vec_append(data, v);
    }, [](){});
  };

  fields->auth_table.do_all_readonly(at, kv);

  //write to file
  string tmp_filename = fields->filename.c_str();
  tmp_filename.append(".tmp");

  ofstream outFile;
  outFile.open(tmp_filename);
  
  outFile.close();

  if (file_exists(tmp_filename) == false){}

  //rename file
  if (rename(tmp_filename.c_str(), fields->filename.c_str())){}
}

/// Shut down the storage when the server stops.
///
/// NB: this is only called when all threads have stopped accessing the
///     Storage object.  As a result, there's nothing left to do, so it's a
///     no-op.
void Storage::shutdown() {}


/// Create a new key/value mapping in the table
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param key       The key whose mapping is being created
/// @param val       The value to copy into the map
///
/// @returns A vec with the result message
vec Storage::kv_insert(const string &user_name, const string &pass,
                       const string &key, const vec &val)
{

  bool user_authed = auth(user_name, pass);
  if (user_authed == false)
  {
    return vec_from_string(RES_ERR_LOGIN);
  }
 
  if (val.empty()) { return vec_from_string(RES_ERR_NO_DATA); }
  if (!fields->kv_store.insert(key, val)) { return vec_from_string(RES_ERR_KEY);}

  return vec_from_string(RES_OK);
}

  /// Get a copy of the value to which a key is mapped
  ///
  /// @param user_name The name of the user who made the request
  /// @param pass      The password for the user, used to authenticate
  /// @param key       The key whose value is being fetched
  ///
  /// @returns A pair with a bool to indicate error, and a vector indicating the
  ///          data (possibly an error message) that is the result of the
  ///          attempt.
  pair<bool, vec> Storage::kv_get(const string &user_name, const string &pass,
                                  const string &key)
  {
    bool user_authed = auth(user_name, pass);
    if (user_authed == false)
    {
      // cerr << RES_ERR_LOGIN << endl; 
      return {true, vec_from_string(RES_ERR_LOGIN)};
    }

    vec val;
    auto res = fields->kv_store.do_with_readonly(key, [&](const vec &v){ 
      val = v;
    });

    if(res != true){
      return {true, vec_from_string(RES_ERR_KEY)};
    }

    if(val.empty()){
      return {true, vec_from_string(RES_ERR_NO_DATA)};
    }

    return {false, val};
  } 

  /// Delete a key/value mapping
  ///
  /// @param user_name The name of the user who made the request
  /// @param pass      The password for the user, used to authenticate
  /// @param key       The key whose value is being deleted
  ///
  /// @returns A vec with the result message
  vec Storage::kv_delete(const string &user_name, const string &pass,
                        const string &key)
  {
    bool user_authed = auth(user_name, pass);
    if (user_authed == false)
    {
      // cerr << RES_ERR_LOGIN << endl;
     
      return vec_from_string(RES_ERR_LOGIN);
    }

    if (!fields->kv_store.remove(key)) { return vec_from_string(RES_ERR_KEY); }
    return vec_from_string(RES_OK);
  }

  /// Insert or update, so that the given key is mapped to the give value
  ///
  /// @param user_name The name of the user who made the request
  /// @param pass      The password for the user, used to authenticate
  /// @param key       The key whose mapping is being upserted
  /// @param val       The value to copy into the map
  ///
  /// @returns A vec with the result message.  Note that there are two "OK"
  ///          messages, depending on whether we get an insert or an update.
  vec Storage::kv_upsert(const string &user_name, const string &pass,
                         const string &key, const vec &val)
  {
    //auth user ----> auth(name, pass)
    //check if key exists in fields->kv_store, using hashtable.h methods
    //if key found ---> change val and return vec_from_string(OK)
    // else insert key ---> hastable.h insert
    //return vec_from_string(OK)
  
    bool user_authed = auth(user_name, pass);
    if (user_authed == false)
    {
      // cerr << RES_ERR_LOGIN << endl;
      return vec_from_string(RES_ERR_LOGIN);
    }

    // upsert == false means val was updated
    if (!fields->kv_store.upsert(key, val)) { return vec_from_string(RES_OKUPD); }
    else { return vec_from_string(RES_OKINS); }

   
  }

  /// Return all of the keys in the fields->kv_store, as a "\n"-delimited string
  ///
  /// @param user_name The name of the user who made the request
  /// @param pass      The password for the user, used to authenticate
  ///
  /// @returns A pair with a bool to indicate errors, and a vec with the result
  ///          (possibly an error message).
  pair<bool, vec> Storage::kv_all(const string &user_name, const string &pass)
  {
    //auth user ----> auth(name, pass)
    //check if key exists in fields->kv_store, using hashtable.h methods
    //call hashtable.h read_all ----> return any error
    //return {false, result from read_all}

    //auth user
    bool user_authed = auth(user_name, pass);
    if (user_authed == false)
    {
      // cerr << RES_ERR_LOGIN << endl;
      return {true, vec_from_string(RES_ERR_LOGIN)};
    }

    vec keys;
    //do_all_readonly takes std::function<void(const K, const V &)> f
    auto at = [&](const string k ,const vec &v){
      vec_append(keys, k);
      vec_append(keys, "\n");
    };

    fields->kv_store.do_all_readonly(at, [](){});

    return {false, keys};
  }