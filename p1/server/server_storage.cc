#include <iostream>
#include <fstream>
#include <string.h>
#include <openssl/md5.h>
#include <unordered_map>
#include <utility>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"
#include "../common/vec.h"
#include "../common/file.h"

#include "server_storage.h"

using namespace std;
/// Storage::Internal is the private struct that holds all of the fields of the
/// Storage object.  Organizing the fields as an Internal is part of the PIMPL
/// pattern.
struct Storage::Internal {
  /// AuthTableEntry represents one user stored in the authentication table
  struct AuthTableEntry {
    /// The name of the user; max 64 characters
    string username;

    /// The hashed password.  Note that the password is a max of 128 chars
    string pass_hash;

    /// The user's content
    vec content;
  };

  /// A unique 8-byte code to use as a prefix each time an AuthTable Entry is
  /// written to disk.
  ///
  /// NB: this isn't needed in assignment 1, but will be useful for backwards
  ///     compatibility later on.
  inline static const string AUTHENTRY = "AUTHAUTH";

  /// The map of authentication information, indexed by username
  unordered_map<string, AuthTableEntry> auth_table;

  /// filename is the name of the file from which the Storage object was loaded,
  /// and to which we persist the Storage object every time it changes
  string filename = "";

  /// Construct the Storage::Internal object by setting the filename
  ///
  /// @param fname The name of the file that should be used to load/store the
  ///              data
  Internal(const string &fname) : filename(fname) {}
};

/// Construct an empty object and specify the file from which it should be
/// loaded.  To avoid exceptions and errors in the constructor, the act of
/// loading data is separate from construction.
///
/// @param fname The name of the file that should be used to load/store the
///              data
Storage::Storage(const string &fname) : fields(new Internal(fname)) {}

/// Destructor for the storage object.
///
/// NB: The compiler doesn't know that it can create the default destructor in
///     the .h file, because PIMPL prevents it from knowing the size of
///     Storage::Internal.  Now that we have reified Storage::Internal, the
///     compiler can make a destructor for us.
Storage::~Storage() = default;

/// Populate the Storage object by loading an auth_table from this.filename.
/// Note that load() begins by clearing the auth_table, so that when the call
/// is complete, exactly and only the contents of the file are in the
/// auth_table.
///
/// @returns false if any error is encountered in the file, and true
///          otherwise.  Note that a non-existent file is not an error.
bool Storage::load() {
  //check file exists
  if(file_exists(fields->filename) == false){
    return true;
  }

  //clear auth table
  fields->auth_table.clear();

  //load auth table from file
  //open the file
  std::ifstream myFile (fields->filename, ios::in | ios::binary);
  std::string line;

  //read through file
  if(myFile.good()){
    while(getline(myFile, line)){
      if(line.substr(0,8).compare("AUTHAUTH") != 0){
        myFile.close();
        return false;
      }
      int username_length = std::atoi(line.substr(8,4).c_str());
      if(username_length > LEN_UNAME){
        myFile.close();
        return false;
      }
      std::string username = line.substr(12, username_length);
      int pass_hash_length = std::atoi(line.substr(12 + username_length, 4).c_str());
      if(pass_hash_length > LEN_PASS){
        myFile.close();
        return false;
      }
      std::string pass_hash = line.substr(12 + username_length + 4, pass_hash_length);
      int content_size = std::atoi(line.substr(12 + username_length + 4 + pass_hash_length, 4).c_str());
      std::string content_data = line.substr(12 + username_length + 4 + pass_hash_length + 4, content_size);

      //set Entry data
      Internal::AuthTableEntry entry;
      entry.username = username;
      entry.pass_hash = pass_hash;

      //clear content vector so it doesn't stack acrossed entries
      entry.content.clear();
      vec new_entry_content = vec_from_string(content_data);
      entry.content = new_entry_content;

      fields->auth_table.insert({username, entry});
    }
    myFile.close();
  }

  //rename file
  std::rename("this.filename.tmp", "this.filename");
  //success
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
bool Storage::add_user(const string &user_name, const string &pass) {
  //check if username is too long
  if(user_name.length() > LEN_UNAME){
    cerr << "Username too long.\n" << endl;
    return false;
  }
  
  //check if username exists
  if(!(fields->auth_table.find(user_name) == fields->auth_table.end())){
    cerr << RES_ERR_USER_EXISTS << endl;
    return false;
  }

  //check if pass_hash is too long
  if(pass.length() > LEN_PASS){
    cerr << "Password too long.\n" << endl;
    return false;
  }
  
  //hash the password
  size_t pass_hash = std::hash<std::string>{}(pass);

  //set Entry data
  Internal::AuthTableEntry entry;
  entry.username = user_name;
  entry.pass_hash = pass_hash;

  //clear content vector so it doesn't stack acrossed entries
  entry.content.clear();
  entry.content = {};

  fields->auth_table.insert({user_name, entry});

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
                           const vec &content) {

  //auth user
  bool user_authed = auth(user_name, pass);
  if(user_authed == false){
    cerr << RES_ERR_LOGIN << endl;
    return vec_from_string("ERR_LOGIN");
  }

  //find user
  //std::unordered_map<std::string,Internal::AuthTableEntry>::const_iterator
  auto  user_data = fields->auth_table;
  if (user_data.find(user_name) == fields->auth_table.end()){
    return vec_from_string("ERR_NO_USER");
  }

  //overwrite user data - http://www.cplusplus.com/reference/unordered_map/unordered_map/operator[]/
  user_data[user_name].content = content;

  return vec_from_string(RES_OK);
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
                                       const string &pass, const string &who) {

  //auth user
  bool user_authed = auth(user_name, pass);
  if(user_authed == false){
    cerr << RES_ERR_LOGIN << endl;
    return {true,vec_from_string("ERR_LOGIN")};
  }                                         

  //find user
  std::unordered_map<std::string,Internal::AuthTableEntry>::const_iterator user_entry = fields->auth_table.find(who);

  //check username exists
  if (user_entry == fields->auth_table.end()){
    cerr << RES_ERR_NO_USER << endl;
    return {true, vec_from_string("ERR_NO_USER")};
  }

  //check if empty data
  if(user_entry->second.content.empty()){
    cerr << RES_ERR_NO_DATA << endl;
    return {true, vec_from_string("ERR_NO_DATA")};
  }
  return {false, user_entry->second.content};
}

/// Return a newline-delimited string containing all of the usernames in the
/// auth table
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns A vector with the data, or a vector with an error message
pair<bool, vec> Storage::get_all_users(const string &user_name,
                                       const string &pass) {
  //auth user
  bool user_authed = auth(user_name, pass);
  if(user_authed == false){
    cerr << RES_ERR_LOGIN << endl;
    return {true,vec_from_string("ERR_LOGIN")};
  }

  //find user
  std::unordered_map<std::string,Internal::AuthTableEntry>::const_iterator user_entry = fields->auth_table.find(user_name);
  
  //check username exists
  if (user_entry == fields->auth_table.end()){
    cerr << RES_ERR_NO_USER << endl;
    return {true, vec_from_string("ERR_NO_USER")};
  }

  //Get an iterator pointing to begining of map
  std::unordered_map<std::string, Internal::AuthTableEntry>::iterator it = fields->auth_table.begin();
  
  //Iterate over the map using iterator
  //get all names from auth table and put them in a string line by line
  vec names;
  while(it != fields->auth_table.end())
  {
    vec_append(names, it->first);
    vec_append(names, "\n");
    it++;
  }
  
  //return no error and string of names
  //pair<vector<pair<bool, std::vector>>> pair_to_ret (false, names);
  return {true, names};
}

/// Authenticate a user
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns True if the user and password are valid, false otherwise
bool Storage::auth(const string &user_name, const string &pass) {
  std::unordered_map<std::string, Internal::AuthTableEntry>::const_iterator user_entry = fields->auth_table.find(user_name);

  //check username exists
  if (user_entry == fields->auth_table.end()){
    cerr << RES_ERR_NO_USER << endl;
    return false;
  }
  
  //get two hashes
  std::string found_pass_hash = (user_entry->second).pass_hash;
  std::size_t given_pass_hash = std::hash<std::string>{}(pass);
  std::string given_pass_hash_str = to_string(given_pass_hash);

  //check pass hash's
  if(found_pass_hash.compare(given_pass_hash_str) != 0){
    cerr << RES_ERR_LOGIN << endl;
    return false;
  }
  return true;
}

/// Write the entire Storage object (right now just the Auth table) to the
/// file specified by this.filename.  To ensure durability, Storage must be
/// persisted in two steps.  First, it must be written to a temporary file
/// (this.filename.tmp).  Then the temporary file can be renamed to replace
/// the older version of the Storage object.
void Storage::persist() { 
  //http://www.cplusplus.com/reference/string/string/length/  

  // Get an iterator pointing to begining of map
  std::unordered_map<std::string, Internal::AuthTableEntry>::iterator it = fields->auth_table.begin();

  vec data;
  data.reserve(LEN_CONTENT);

  //loop through unordered_map
  while(it != fields->auth_table.end()){

    //save user from auth_table entry to file
    vec_append(data, "AUTHAUTH");
    vec_append(data, it->second.username.length());
    vec_append(data, it->second.username);
    vec_append(data, it->second.pass_hash.length());
    vec_append(data, it->second.pass_hash);
    vec_append(data, it->second.content.size());  
    if(it->second.content.size() > 0){
      vec_append(data, it->second.content);
    }
    vec_append(data, "\n");  
    it++;
  }

  //write to file
  string tmp_filename = fields->filename.c_str();
  tmp_filename.append(".tmp");
  if(write_file(tmp_filename.c_str(), reinterpret_cast<const char*>(data.data()), data.size())){
    cerr << "error persisting to tmp file" << endl;
  }

  //rename file
  if(write_file(fields->filename.c_str(), reinterpret_cast<const char*>(data.data()), data.size())){
      cerr << "error persisting to file" << endl;
    }

}

/// Shut down the storage when the server stops.
///
/// NB: this is only called when all threads have stopped accessing the
///     Storage object.  As a result, there's nothing left to do, so it's a
///     no-op.
void Storage::shutdown() {}
