#include <iostream>
#include <openssl/md5.h>
#include <unordered_map>
#include <utility>
#include <fstream>
#include <sys/stat.h>
#include <string.h>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/hashtable.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "server_storage.h"

using namespace std;

/// Storage::Internal is the private struct that holds all of the fields of
/// the Storage object.  Organizing the fields as an Internal is part of the
/// PIMPL pattern.
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

  /// A unique 8-byte code for incremental persistence of changes to the auth
  /// table
  inline static const string AUTHDIFF = "AUTHDIFF";

  /// A unique 8-byte code for incremental persistence of updates to the kv
  /// store
  inline static const string KVUPDATE = "KVUPDATE";

  /// A unique 8-byte code for incremental persistence of deletes to the kv
  /// store
  inline static const string KVDELETE = "KVDELETE";

  /// The map of authentication information, indexed by username
  ConcurrentHashTable<string, AuthTableEntry> auth_table;

  /// The map of key/value pairs
  ConcurrentHashTable<string, vec> kv_store;

  /// filename is the name of the file from which the Storage object was loaded,
  /// and to which we persist the Storage object every time it changes
  string filename = "";

  //keep an openfile
  std::fstream myFile;

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

/// Pad a string with 0 characters to get it to size 4
void pad0_to_4(string &s)
{
  // check if  vec is larger than sz
  if (s.length() >= 4)
  {
    //do nothing --- we dont need to pad
  }
  s.insert(s.begin(), 4 - s.length(), '0');
}

/// Populate the Storage object by loading this.filename.  Note that load()
/// begins by clearing the maps, so that when the call is complete, exactly and
/// only the contents of the file are in the Storage object.
///
/// @returns false if any error is encountered in the file, and true otherwise.
///          Note that a non-existent file is not an error.
bool Storage::load()
{
  FILE *f = fopen(fields->filename.c_str(), "r");
  if (f == nullptr)
  {
    cerr << "File not found: " << fields->filename << endl;
    fields->myFile.open(fields->filename, ios::binary | std::fstream::app);
    return true;
  }
  fclose(f);

  //clear
  fields->auth_table.clear();
  fields->kv_store.clear();

  //open the file
  fields->myFile.open(fields->filename, ios::in | ios::binary);

  //load auth table from file
  if (fields->myFile.good())
  {
    while (!fields->myFile.eof())
    {

      char h[9];
      fields->myFile.read(h, 8);
      h[8] = '\0';
      string header(h);

      //check if AUTHAUTH
      if (header.compare(fields->AUTHENTRY) == 0)
      {
        //read username length
        int temp;
        fields->myFile.read((char *)&temp, 4);
        if (temp > LEN_UNAME)
        {
          fields->myFile.close();
          return false;
        }

        //read username
        char u[temp + 1];
        fields->myFile.read(u, temp);
        u[temp] = '\0';
        string username(u);

        int temp2;
        fields->myFile.read((char *)&temp2, 4);

        if (temp2 > LEN_PASS)
        {
          fields->myFile.close();
          return false;
        }

        //read pass hash
        char ph[temp2 + 1];
        fields->myFile.read(ph, temp2);
        ph[temp2] = '\0';

        string pass_hash(ph);

        //read content size
        int temp3;
        fields->myFile.read((char *)&temp3, 4);

        //int content_size = atoi(cs);
        if (temp3 > LEN_CONTENT)
        {
          fields->myFile.close();
          return false;
        }

        //set Entry data
        Internal::AuthTableEntry entry;

        if (temp3 > 0)
        {
          //read content data
          vec content_data(temp3);
          fields->myFile.read((char *) content_data.data(), temp3);

          entry.username = username;
          entry.pass_hash = pass_hash;
          entry.content = content_data;
        }
        else
        {
          entry.username = username;
          entry.pass_hash = pass_hash;
          entry.content = {};

          string u1 = entry.username;
          string p1 = entry.pass_hash;
        }
        fields->auth_table.insert(username, entry, []() {});
      }
      else if (header.compare(fields->KVENTRY) == 0)
      {
        int kl;
        fields->myFile.read((char *)&kl, 4);

        //cerr << "kl: ";
        //cerr << kl << endl;

        if (kl > LEN_KEY)
        {
          fields->myFile.close();
          return false;
        }

        //cerr << "keylength: ";
        //cerr << key_length << endl;

        //get the key
        char k[kl + 1];
        fields->myFile.read(k, kl);
        k[kl] = '\0';
        string key(k);

        //cerr << "key: ";
        //cerr << key << endl;

        //get val length and check
        int vl;
        fields->myFile.read((char *)&vl, 4);

        if (vl > LEN_VAL)
        {
          fields->myFile.close();
          return false;
        }

        //get val
        vec val_vec(vl);
        fields->myFile.read((char*)val_vec.data(), vl);

        fields->kv_store.insert(key, val_vec, []() {});
      }
      else if (header.compare(fields->AUTHDIFF) == 0)
      {
        //read username length
        int ul;
        fields->myFile.read((char *)&ul, 4);

        //cerr << "ul: ";
        //cerr << ul << endl;

        if (ul > LEN_UNAME)
        {
          fields->myFile.close();
          return false;
        }

        //cerr << "u length: ";
        //cerr << username_length <<endl;

        //read username
        char u[ul + 1];
        fields->myFile.read(u, ul);
        u[ul] = '\0';

        //cerr << "u: ";
        //cerr << u << endl;

        string username(u);

        //cerr << "user: ";
        //cerr << username <<endl;

        //read content size
        int cs;
        fields->myFile.read((char *)&cs, 4);

        //cerr << "cs: ";
        //cerr << cs << endl;

        if (cs > LEN_CONTENT)
        {
          fields->myFile.close();
          return false;
        }

        //cerr << "content size: ";
        //cerr << content_size <<endl;

        //set Entry data
        Internal::AuthTableEntry entry;
        fields->auth_table.do_with_readonly(username, [&](const Internal::AuthTableEntry &e) {
          entry.username = e.username;
          entry.pass_hash = e.pass_hash;
        });

        if (cs > 0)
        {
          //read content data
          vec content_data(cs);
          fields->myFile.read((char*)content_data.data(), cs);

          entry.content = content_data;
        }
        else
        {
          entry.content = {};
          string u1 = entry.username;
          //cerr << u1 << endl;
          //cerr << "content size == 0 "<<endl;
        }
        fields->auth_table.upsert(username, entry, []() {}, []() {});
      }
      else if (header.compare(fields->KVDELETE) == 0)
      {
        int kl;
        fields->myFile.read((char *)&kl, 4);

        //cerr << kl << endl;

        if (kl > LEN_KEY)
        {
          fields->myFile.close();
          return false;
        }

        //get the key
        char k[kl + 1];
        fields->myFile.read(k, kl);
        k[kl] = '\0';
        //cerr << k << endl;
        string key(k);

        //cerr << key << endl;

        fields->kv_store.remove(key, [](){});
      }
      else if (header.compare(fields->KVUPDATE) == 0)
      {
        int kl;
        fields->myFile.read((char *)&kl, 4);

        //cerr << "kl: ";
        //cerr << kl << endl;

        if (kl > LEN_KEY)
        {
          fields->myFile.close();
          return false;
        }

        //cerr << "keylength: ";
        //cerr << key_length << endl;

        //get the key
        char k[kl + 1];
        fields->myFile.read(k, kl);
        k[kl] = '\0';
        string key(k);

        //cerr << "key: ";
        //cerr << key << endl;

        //get val length and check
        int vl;
        fields->myFile.read((char *)&vl, 4);

        if (vl > LEN_VAL)
        {
          fields->myFile.close();
          return false;
        }

        //get val
        vec val_vec(vl);
        fields->myFile.read((char*)val_vec.data(), vl);

        fields->kv_store.upsert(key, val_vec, [](){}, [](){});
      }
      else
      {
        //no eof and read wrong bytes
        fields->myFile.close();
        return false;
      }
    }
    //close file
    fields->myFile.close();

    //open in append mode
    fields->myFile.open(fields->filename, std::fstream::out | std::fstream::app);
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
  //same as P2
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

  //check if user_name already exists
  fields->auth_table.do_with_readonly(user_name, [&](const Internal::AuthTableEntry &e) {
    //use e to set b
    if (e.username == user_name)
    {
      //cerr << RES_ERR_USER_EXISTS << endl;
      b = false;
    }
  });
  if (b == false)
  {
    return false;
  }

  //hash the password
  unsigned char digest[MD5_DIGEST_LENGTH + 1] = {0};
  MD5((unsigned char *)pass.c_str(), strlen(pass.c_str()), digest);
  string pass_hash_string((const char *)digest);

  //set Entry data
  Internal::AuthTableEntry entry;
  entry.username = user_name;
  entry.pass_hash = pass_hash_string;
  entry.content = {};

  //cerr << "add_user: password: ";
  //cerr << entry.pass_hash << endl;

  //AUTHAUTH lambda
  vec data;

  //cerr << "before insert lambda" <<endl;

  auto insert_lambda = [&]() {
    //cerr << "In insert lambda" << endl;
    //save user from auth_table entry to file
    vec_append(data, "AUTHAUTH");

    vec_append(data, entry.username.length());
    vec_append(data, entry.username);

    vec_append(data, entry.pass_hash.length());
    vec_append(data, entry.pass_hash);

    vec_append(data, entry.content.size());

    if (entry.content.size() > 0)
    {
      vec_append(data, entry.content);
    }
    fields->myFile.write((const char *)data.data(), data.size());
    fields->myFile.flush();
  };

  //insert lambda runs on success so, e should be intitialized if so
  if (fields->auth_table.insert(user_name, entry, insert_lambda) == false)
  {
    //cerr << "insert error -- close file here??" << endl;
    return false;
  }

  return true;
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

  ///need to write AUTHDIFF to file

  //auth user
  bool user_authed = auth(user_name, pass);
  if (user_authed == false)
  {
    return vec_from_string(RES_ERR_LOGIN);
  }

  if (content.empty())
  {
    return vec_from_string(RES_ERR_NO_DATA);
  }

  Internal::AuthTableEntry entry;
  entry.username = user_name;

  //hash the password
  unsigned char digest[MD5_DIGEST_LENGTH + 1] = {0};
  MD5((unsigned char *)pass.c_str(), strlen(pass.c_str()), digest);
  string given_pass_hash_str((const char *)digest);

  entry.pass_hash = given_pass_hash_str;
  entry.content = content;

  //cerr << "set_user_data pass_hash: ";
  //cerr << entry.pass_hash << endl;

  vec data;

  //lambdas for AUTHAUTH
  auto on_ins = [&]() {
    //save user from auth_table entry to file
    vec_append(data, "AUTHAUTH");

    vec_append(data, entry.username.length());
    vec_append(data, entry.username);

    vec_append(data, entry.pass_hash.length());
    vec_append(data, entry.pass_hash);

    vec_append(data, entry.content.size());
    if (entry.content.size() > 0)
    {
      vec_append(data, entry.content);
    }
    //save to file
    fields->myFile.write((const char *)data.data(), data.size());
    //flush file
    fields->myFile.flush();
  };

  // lambdas for AUTHDIFF
  auto on_upd = [&]() {
    //save user from auth_table entry to file
    vec_append(data, "AUTHDIFF");

    vec_append(data, entry.username.length());
    vec_append(data, entry.username);

    vec_append(data, entry.content.size());
    if (entry.content.size() > 0)
    {
      vec_append(data, entry.content);
    }
    //save to file
    fields->myFile.write((const char *)data.data(), data.size());
    //flush file
    fields->myFile.flush();
  };

  if (fields->auth_table.upsert(user_name, entry, on_ins, on_upd) == false)
  {
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

  //same as P2

  //auth user
  bool user_authed = auth(user_name, pass);
  if (user_authed == false)
  {
    // //cerr << RES_ERR_LOGIN << endl;
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }

  pair<bool, vec> b = {};
  auto res = fields->auth_table.do_with_readonly(who, [&](const Internal::AuthTableEntry &e) {
    //use e to set b
    if (e.username != who)
    {
      b = {true, vec_from_string(RES_ERR_NO_USER)};
    }
    else if (e.username == who && !e.content.empty())
    {
      b = {false, e.content};
    }
    else
    {
      b = {true, vec_from_string(RES_ERR_NO_DATA)};
    }
  });

  if (res == false)
  {
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
  //same as P2
  //auth user
  bool user_authed = auth(user_name, pass);
  if (user_authed == false)
  {
    // //cerr << RES_ERR_LOGIN << endl;
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }

  vec names;
  //do_all_readonly takes std::function<void(const K, const V &)> f
  auto at = [&](const string k, const Internal::AuthTableEntry &e) {
    vec_append(names, k);
    vec_append(names, "\n");
  };

  fields->auth_table.do_all_readonly(at, []() {});
  return {false, names};
}

/// Authenticate a user
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns True if the user and password are valid, false otherwise
bool Storage::auth(const string &user_name, const string &pass)
{
  //same as p2
  bool b = true;

  //hash the password
  unsigned char digest[MD5_DIGEST_LENGTH + 1] = {0};
  MD5((unsigned char *)pass.c_str(), strlen(pass.c_str()), digest);
  string given_pass_hash_str((const char *)digest);

  auto res = fields->auth_table.do_with_readonly(user_name, [&](const Internal::AuthTableEntry &e) {
    //use e to set b
    if (e.username != user_name)
    {
      //cerr << RES_ERR_NO_USER << endl;
      b = false;
    }
    else if (e.pass_hash.compare(given_pass_hash_str) != 0)
    {
      //cerr << "error login in auth()" << endl;
      b = false;
    }
  });

  if (res == false)
  {
    //cerr << "key failure in auth for do_with_readonly" <<endl;
    b = false;
  }

  return b;
}

/// Write the entire Storage object to the file specified by this.filename.
/// To ensure durability, Storage must be persisted in two steps.  First, it
/// must be written to a temporary file (this.filename.tmp).  Then the
/// temporary file can be renamed to replace the older version of the Storage
/// object.
void Storage::persist()
{
  vec data;

  auto at = [&](const string k, const Internal::AuthTableEntry &e) {
    //save user from auth_table entry to file
    vec_append(data, "AUTHAUTH");

    //username
    vec_append(data, e.username.length());
    vec_append(data, e.username);

    //pass
    vec_append(data, e.pass_hash.length());
    vec_append(data, e.pass_hash);

    vec_append(data, e.content.size());

    if (e.content.size() > 0)
    {
      vec_append(data, e.content);
    }
  };

  auto kv = [&]() {
    fields->kv_store.do_all_readonly([&](const string k, const vec &v) {
    vec_append(data, "KVKVKVKV");

    vec_append(data, k.size());
    vec_append(data, k);

    vec_append(data, v.size());
    vec_append(data, v); 

    }, [](){});
  };

  fields->auth_table.do_all_readonly(at, kv);

  //create tmp file
  string tmp_filename = fields->filename.c_str();
  tmp_filename.append(".tmp");

  //write to tmp file
  ofstream outFile;
  outFile.open(tmp_filename, ios::out | ios::binary);
  outFile.write((const char *)data.data(), data.size());
  outFile.close();

  //check tmp file exists
  struct stat buffer;
  if (stat(tmp_filename.c_str(), &buffer) == 0){}

  //close myFile
  fields->myFile.close();

  //rename file - should overwrite myFile
  if (rename(tmp_filename.c_str(), fields->filename.c_str())){}

  //reopen file in append mode -- shutdown should close file
  fields->myFile.open(fields->filename, std::fstream::out | std::fstream::app);
}

/// Close any open files related to incremental persistence
///
/// NB: this cannot be called until all threads have stopped accessing the
///     Storage object
void Storage::shutdown()
{
  fields->myFile.close();
}

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
  //insert shouldn't change
  bool user_authed = auth(user_name, pass);
  if (user_authed == false)
  {
    return vec_from_string(RES_ERR_LOGIN);
  }

  if (val.empty())
  {
    return vec_from_string(RES_ERR_NO_DATA);
  }

  //KVKVKVKV lambda
  vec data;

  //auto kv = [&](){fields->kv_store.do_all_readonly([&](const string k, const vec &v){
  //    auto res = fields->kv_store.do_with_readonly(key, [&](const vec &v){
  auto insert_lambda = [&]() {
    vec_append(data, "KVKVKVKV");

    vec_append(data, key.size());
    vec_append(data, key);

    vec_append(data, val.size());
    vec_append(data, val);

    //save to file
    fields->myFile.write((const char *)data.data(), data.size());
    //flush file
    fields->myFile.flush();
  };

  if (!fields->kv_store.insert(key, val, insert_lambda))
  {
    return vec_from_string(RES_ERR_KEY);
  }

  return vec_from_string(RES_OK);
};

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
  //same as P2
  bool user_authed = auth(user_name, pass);
  if (user_authed == false)
  {
    // //cerr << RES_ERR_LOGIN << endl;
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }

  vec val;
  auto res = fields->kv_store.do_with_readonly(key, [&](const vec &v) {
    val = v;
  });

  if (res != true)
  {
    return {true, vec_from_string(RES_ERR_KEY)};
  }

  if (val.empty())
  {
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
    return vec_from_string(RES_ERR_LOGIN);
  }

  //KVDELETE Lambda
  vec data;

  //auto insert_lambda = [&](){fields->auth_table.do_with_readonly(user_name, [&](const Internal::AuthTableEntry &e){
  auto delete_lambda = [&]() {
    vec_append(data, "KVDELETE");

    vec_append(data, key.size());
    vec_append(data, key);

    //save to file
    fields->myFile.write((const char *)data.data(), data.size());
    //flush file
    fields->myFile.flush();
  };

  if (!fields->kv_store.remove(key, delete_lambda))
  {
    return vec_from_string(RES_ERR_KEY);
  }

  return vec_from_string(RES_OK);
};

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

  bool user_authed = auth(user_name, pass);
  if (user_authed == false)
  {
    return vec_from_string(RES_ERR_LOGIN);
  }

  //KVKVKVKV lambda
  vec data;

  auto on_ins = [&]() {
    //use const
    vec_append(data, "KVKVKVKV");

    vec_append(data, key.size());
    vec_append(data, key);

    vec_append(data, val.size());
    vec_append(data, val);

    //save to file
    fields->myFile.write((const char *)data.data(), data.size());
    //flush file
    fields->myFile.flush();
  };

  //KVUPDATE
  auto on_upd = [&]() {
    vec_append(data, "KVUPDATE");

    vec_append(data, key.size());
    vec_append(data, key);

    vec_append(data, val.size());
    vec_append(data, val);

    //save to file
    fields->myFile.write((const char *)data.data(), data.size());
    //flush file
    fields->myFile.flush();
  };

  // upsert == false means val was updated
  if (!fields->kv_store.upsert(key, val, on_ins, on_upd))
  {
    return vec_from_string(RES_OKUPD);
  }

  return vec_from_string(RES_OKINS);
};

/// Return all of the keys in the kv_store, as a "\n"-delimited string
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns A pair with a bool to indicate errors, and a vec with the result
///          (possibly an error message).
pair<bool, vec> Storage::kv_all(const string &user_name, const string &pass)
{
  //auth user
  bool user_authed = auth(user_name, pass);
  if (user_authed == false)
  {
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }

  vec keys;
  auto at = [&](const string k, const vec &v) {
    vec_append(keys, k);
    vec_append(keys, "\n");
  };

  fields->kv_store.do_all_readonly(at, []() {});

  return {false, keys};
};
